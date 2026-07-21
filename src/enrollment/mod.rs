//! The enrollment client: proves key possession to the QuartzCommand
//! EnrollmentService and receives the mTLS client certificate for the
//! control channel.
//!
//! Flow (see the enrollment.proto contract):
//! 1. TLS to the token's gateway, no client cert; the token's `sha256:` CA
//!    fingerprint is the trust anchor for this bootstrap connection
//!    (src/tls.rs — pin the issuing CA, don't rely on public roots).
//! 2. `BeginEnrollment(token_id, pubkey)` → nonce + session id.
//! 3. Sign the nonce, build a CSR (CN = device id, same Ed25519 key),
//!    `CompleteEnrollment(secret, device_id, signature, CSR, hostname,
//!    version)`.
//! 4. Verify the returned CA chain against the token's fingerprint and
//!    return the issued cert + chain + assigned gateway; the caller
//!    persists them.
//!
//! The controller's failures are deliberately uniform (NOT_FOUND at begin,
//! PERMISSION_DENIED at complete), so error mapping keeps the operator
//! message equally uniform: "check the token". The endpoint is rate-limited
//! per source IP — a failure is surfaced once, never hot-retried.

use anyhow::{Context, Result};
use rustls::RootCertStore;
use sha2::{Digest, Sha256};

use crate::control::tls::{self, VerifiedVia};
use crate::identity::deviceid;
use crate::identity::KeyBackend;
use crate::proto::enrollment::enrollment_service_client::EnrollmentServiceClient;
use crate::proto::enrollment::{BeginEnrollmentRequest, CompleteEnrollmentRequest};
use self::token::EnrollToken;

pub mod token;

#[cfg(test)]
mod mock_tests;

pub struct EnrollRequest<'a> {
    pub token: &'a EnrollToken,
    pub hostname: String,
    /// This agent's own version; the shared fleet-wide proto field is named
    /// `qf_version`.
    pub agent_version: String,
}

#[derive(Debug)]
pub struct EnrollOutcome {
    pub device_id: String,
    pub org_id: String,
    pub client_cert_der: Vec<u8>,
    pub ca_chain_der: Vec<Vec<u8>>,
    /// Empty from the server means "keep using the token's gateway".
    pub assigned_gateway: Option<String>,
    /// DER of the CA cert that matched the token's fingerprint during the
    /// TLS handshake — persisted for future connections.
    pub pinned_ca_der: Option<Vec<u8>>,
    pub cert_not_before_unix: i64,
    pub cert_not_after_unix: i64,
    /// 2/3 of the cert lifetime — the renewal point.
    pub renew_after_unix: i64,
}

/// Build the CSR: CN = device id, signed with the device key.
pub fn build_csr(key: &dyn KeyBackend, device_id: &str) -> Result<Vec<u8>> {
    let pkcs8 = key.pkcs8_der()?;
    let keypair = rcgen::KeyPair::try_from(pkcs8.as_slice()).context("load key for CSR")?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, device_id);
    let csr = params.serialize_request(&keypair).context("sign CSR")?;
    Ok(csr.der().to_vec())
}

/// Compute the 2/3-of-lifetime renewal point from cert validity.
pub fn renew_after(not_before: i64, not_after: i64) -> i64 {
    not_before + (not_after - not_before) * 2 / 3
}

/// Parse validity (unix seconds) out of a DER certificate.
pub fn cert_validity(der: &[u8]) -> Result<(i64, i64)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| anyhow::anyhow!("issued certificate does not parse: {e}"))?;
    let v = cert.validity();
    Ok((v.not_before.timestamp(), v.not_after.timestamp()))
}

pub async fn enroll(key: &dyn KeyBackend, req: EnrollRequest<'_>) -> Result<EnrollOutcome> {
    let token = req.token;
    let device_id = deviceid::derive_device_id(&key.public_key_raw());

    // Bootstrap trust: the token's CA fingerprint only — no public roots, no
    // client cert (the enrollment service is served without one).
    let (tls_config, outcome) =
        tls::client_config(RootCertStore::empty(), Some(token.ca_fingerprint), None)?;

    let channel = tls::grpc_channel(
        &token.gateway_host,
        token.gateway_port,
        tls_config,
        std::time::Duration::from_secs(15),
    )
    .await
    .map_err(|e| map_connect_error(e, token))?;

    let trust = outcome
        .lock()
        .unwrap()
        .clone()
        .context("TLS handshake completed without recording a trust path (bug)")?;
    let pinned_ca_der = match trust {
        VerifiedVia::Pinned(der) => {
            tracing::info!(
                gateway = %token.gateway(),
                "gateway TLS validated via the token's CA fingerprint"
            );
            Some(der)
        }
        VerifiedVia::Roots => None, // unreachable with an empty root store
    };

    let mut client = EnrollmentServiceClient::new(channel);

    let begin = client
        .begin_enrollment(BeginEnrollmentRequest {
            token_id: token.token_id.clone(),
            device_pubkey: key.public_key_raw().to_vec(),
        })
        .await
        .map_err(|s| map_grpc_error("BeginEnrollment", s))?
        .into_inner();
    if begin.nonce.is_empty() {
        anyhow::bail!("controller returned an empty enrollment nonce — controller bug or protocol mismatch");
    }

    let nonce_signature = key.sign(&begin.nonce);
    let csr_der = build_csr(key, &device_id)?;

    let done = client
        .complete_enrollment(CompleteEnrollmentRequest {
            enrollment_session_id: begin.enrollment_session_id,
            token_secret: token.secret.clone(),
            device_id: device_id.clone(),
            nonce_signature,
            csr_der,
            hostname: req.hostname,
            qf_version: req.agent_version,
        })
        .await
        .map_err(|s| map_grpc_error("CompleteEnrollment", s))?
        .into_inner();

    if done.client_cert_der.is_empty() {
        anyhow::bail!("controller returned no client certificate — controller bug or protocol mismatch");
    }
    // The returned CA chain must contain the CA the token pinned — a chain
    // that doesn't is not the controller the operator's token vouched for.
    if !chain_matches_fingerprint(&done.ca_chain_der, &token.ca_fingerprint) {
        anyhow::bail!(
            "the CA chain returned by the controller does not match the enrollment token's \
             CA fingerprint — refusing to trust it (possible controller misconfiguration \
             or man-in-the-middle)"
        );
    }
    let (not_before, not_after) = cert_validity(&done.client_cert_der)?;

    Ok(EnrollOutcome {
        device_id,
        org_id: done.org_id,
        client_cert_der: done.client_cert_der,
        ca_chain_der: done.ca_chain_der,
        assigned_gateway: Some(done.assigned_gateway).filter(|g| !g.is_empty()),
        pinned_ca_der,
        cert_not_before_unix: not_before,
        cert_not_after_unix: not_after,
        renew_after_unix: renew_after(not_before, not_after),
    })
}

/// Whether any certificate in the chain has the pinned SHA-256 fingerprint.
pub fn chain_matches_fingerprint(chain_der: &[Vec<u8>], fingerprint: &[u8; 32]) -> bool {
    chain_der
        .iter()
        .any(|der| <[u8; 32]>::from(Sha256::digest(der)) == *fingerprint)
}

/// Turn transport/TLS failures into operator-actionable messages.
fn map_connect_error(e: anyhow::Error, token: &EnrollToken) -> anyhow::Error {
    let text = format!("{e:#}");
    let gateway = token.gateway();
    if text.contains("does not match the token's CA fingerprint") {
        return anyhow::anyhow!(
            "cannot trust {gateway}: {text}. If the controller's certificate was rotated, \
             issue a fresh enrollment token."
        );
    }
    if text.contains("Expired") || text.contains("NotValidYet") || text.contains("InvalidCertificate") {
        return anyhow::anyhow!(
            "TLS to {gateway} failed: {text}. If this mentions certificate validity, check \
             the switch clock (see 'date') — a wrong clock makes valid certificates look \
             expired or not yet valid."
        );
    }
    if text.contains("dns error")
        || text.contains("failed to lookup")
        || text.contains("resolving gateway host")
    {
        return anyhow::anyhow!(
            "cannot resolve gateway host '{}' ({text}) — check DNS and the token's gateway segment",
            token.gateway_host
        );
    }
    if text.contains("refused") || text.contains("timed out") || text.contains("unreachable") {
        return anyhow::anyhow!(
            "cannot reach QuartzCommand gateway {gateway}: {text}. Check network/firewall \
             egress from this switch (management VRF routing included)."
        );
    }
    anyhow::anyhow!("connecting to QuartzCommand gateway {gateway} failed: {text}")
}

/// Turn gRPC status codes into operator-actionable messages. The controller
/// keeps rejections deliberately uniform, so the message stays friendly and
/// generic: check the token.
fn map_grpc_error(rpc: &str, status: tonic::Status) -> anyhow::Error {
    use tonic::Code;
    let msg = status.message().to_string();
    match status.code() {
        Code::NotFound | Code::PermissionDenied | Code::Unauthenticated => anyhow::anyhow!(
            "enrollment failed — check the token ({rpc}: {msg}). The token may be mistyped, \
             expired, revoked, or already used, or this device may already be adopted (revoke \
             it in the QuartzCommand console first). Issue a fresh token and try again — the \
             endpoint is rate-limited, so wait a moment between attempts."
        ),
        Code::InvalidArgument => {
            anyhow::anyhow!("the controller rejected the enrollment request ({rpc}: {msg})")
        }
        Code::DeadlineExceeded | Code::Unavailable => anyhow::anyhow!(
            "the controller is unreachable mid-enrollment ({rpc}: {msg}) — try again; if \
             this persists, check the gateway address and network path"
        ),
        code => anyhow::anyhow!("enrollment failed ({rpc}: {code:?}: {msg})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Renewal timing math: 2/3 of the lifetime, anchored at not_before.
    #[test]
    fn renew_after_is_two_thirds_of_lifetime() {
        // 90-day cert issued at t=0 → renew at day 60.
        assert_eq!(renew_after(0, 90 * 86_400), 60 * 86_400);
        // Anchored at not_before, not at zero.
        assert_eq!(renew_after(1_000_000, 1_000_000 + 300), 1_000_000 + 200);
        // Degenerate zero-length validity → renew immediately.
        assert_eq!(renew_after(500, 500), 500);
        // Truncation is toward not_before (integer division).
        assert_eq!(renew_after(0, 100), 66);
    }

    #[test]
    fn chain_fingerprint_matching() {
        let ca = b"ca-cert-der".to_vec();
        let other = b"other-cert".to_vec();
        let fp: [u8; 32] = Sha256::digest(&ca).into();
        assert!(chain_matches_fingerprint(&[other.clone(), ca.clone()], &fp));
        assert!(!chain_matches_fingerprint(&[other], &fp));
        assert!(!chain_matches_fingerprint(&[], &fp));
    }
}
