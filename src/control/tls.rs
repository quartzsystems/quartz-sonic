//! TLS for the QuartzCommand gateway connections.
//!
//! tonic's own `tls` feature is deliberately unused: bootstrap trust is the
//! enrollment token's CA fingerprint pin (not public WebPKI roots), which
//! needs a custom rustls verifier, so we build the rustls `ClientConfig`
//! ourselves and hand tonic a ready TLS stream via
//! `Endpoint::connect_with_connector`.
//!
//! Verification policy ([`QsVerifier`]):
//! * With a root store (post-enrollment: the persisted device-CA chain):
//!   normal chain validation against those anchors.
//! * With a fingerprint pin (enrollment bootstrap): find the presented cert
//!   whose SHA-256 (over DER) matches the pin. A matching intermediate
//!   becomes the sole trust anchor for a full re-validation (signature
//!   chain, validity window, hostname). If the match is the end-entity
//!   certificate itself (self-signed gateway), the exact-cert pin is
//!   accepted directly — the fingerprint IS the identity statement.
//! * A chain matching neither is rejected.

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint, Uri};

/// Which trust path a handshake validated through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedVia {
    /// Chain validation against the configured root store.
    Roots,
    /// The DER of the CA (or exact end-entity cert) that matched the pin —
    /// persisted as `pinned-ca.crt` after successful enrollment.
    Pinned(Vec<u8>),
}

/// Shared cell the verifier records its outcome into (one handshake at a
/// time per connect attempt; the last handshake wins, which is the one the
/// established channel used).
pub type VerifyOutcome = Arc<Mutex<Option<VerifiedVia>>>;

#[derive(Debug)]
pub struct QsVerifier {
    roots: Option<Arc<WebPkiServerVerifier>>,
    pin: Option<[u8; 32]>,
    provider: Arc<CryptoProvider>,
    outcome: VerifyOutcome,
}

impl QsVerifier {
    /// `roots` may be empty (the pure pinning path — enrollment bootstrap);
    /// `pin` may be None (post-enrollment connections trusting the persisted
    /// CA chain).
    pub fn new(roots: RootCertStore, pin: Option<[u8; 32]>) -> Result<(Arc<Self>, VerifyOutcome)> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = if roots.is_empty() {
            None
        } else {
            Some(
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()
                    .context("build root-store verifier")?,
            )
        };
        let outcome: VerifyOutcome = Arc::new(Mutex::new(None));
        let verifier = Arc::new(QsVerifier { roots, pin, provider, outcome: outcome.clone() });
        Ok((verifier, outcome))
    }

    fn record(&self, via: VerifiedVia) {
        *self.outcome.lock().unwrap() = Some(via);
    }
}

impl ServerCertVerifier for QsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let roots_err = match &self.roots {
            Some(w) => {
                match w.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                {
                    Ok(ok) => {
                        self.record(VerifiedVia::Roots);
                        return Ok(ok);
                    }
                    Err(e) => Some(e),
                }
            }
            None => None,
        };

        if let Some(pin) = self.pin {
            let mut pin_err: Option<String> = None;
            // Intermediates first (the proper "issuing CA" pin, fully
            // re-validated), the end entity last (self-signed gateway —
            // exact-cert pin).
            for cand in intermediates.iter().chain(std::iter::once(end_entity)) {
                if <[u8; 32]>::from(Sha256::digest(cand.as_ref())) != pin {
                    continue;
                }
                if cand.as_ref() == end_entity.as_ref() {
                    self.record(VerifiedVia::Pinned(cand.as_ref().to_vec()));
                    return Ok(ServerCertVerified::assertion());
                }
                // Re-run full verification with the pinned CA as the sole
                // trust anchor: signature chain, validity, hostname.
                let mut roots = RootCertStore::empty();
                if let Err(e) = roots.add(cand.clone().into_owned()) {
                    pin_err = Some(format!("pinned cert is not usable as a trust anchor: {e}"));
                    continue;
                }
                match WebPkiServerVerifier::builder_with_provider(
                    Arc::new(roots),
                    self.provider.clone(),
                )
                .build()
                {
                    Ok(v) => match v.verify_server_cert(
                        end_entity,
                        intermediates,
                        server_name,
                        ocsp_response,
                        now,
                    ) {
                        Ok(ok) => {
                            self.record(VerifiedVia::Pinned(cand.as_ref().to_vec()));
                            return Ok(ok);
                        }
                        Err(e) => pin_err = Some(e.to_string()),
                    },
                    Err(e) => pin_err = Some(e.to_string()),
                }
            }
            let detail = match (roots_err, pin_err) {
                (_, Some(p)) => format!("CA fingerprint matched but chain validation failed: {p}"),
                (Some(w), None) => {
                    format!("root-store validation failed ({w}) and no presented certificate matches the token's CA fingerprint")
                }
                (None, None) => {
                    "no presented certificate matches the token's CA fingerprint".to_string()
                }
            };
            return Err(rustls::Error::General(format!(
                "server certificate chain does not match the token's CA fingerprint: {detail}"
            )));
        }

        Err(roots_err.unwrap_or_else(|| {
            rustls::Error::General("no trust anchors available for server verification".into())
        }))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

// ── config builders ───────────────────────────────────────────────────────────

/// Only the given PEM anchors (the post-enrollment device-CA trust mode).
pub fn pinned_roots(pems: &[&str]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for pem_text in pems {
        for der in rustls_pemfile::certs(&mut pem_text.as_bytes()) {
            let der = der.context("parse CA certificate PEM")?;
            roots.add(der).context("add CA certificate to the trust store")?;
        }
    }
    if roots.is_empty() {
        return Err(anyhow!("no usable certificates in the pinned CA store"));
    }
    Ok(roots)
}

/// Client config with the quartz-sonic verifier and optional mTLS identity.
pub fn client_config(
    roots: RootCertStore,
    pin: Option<[u8; 32]>,
    client_identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<(ClientConfig, VerifyOutcome)> {
    let (verifier, outcome) = QsVerifier::new(roots, pin)?;
    let builder = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("TLS protocol versions")?
    .dangerous()
    .with_custom_certificate_verifier(verifier);
    let mut config = match client_identity {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .context("load mTLS client identity")?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok((config, outcome))
}

// ── tonic channel over our TLS ────────────────────────────────────────────────

/// Establish a gRPC channel to `host:port` using `tls`. HTTP/2 keepalive
/// pings every 25 s hold the control channel open and detect a dead peer.
pub async fn grpc_channel(
    host: &str,
    port: u16,
    tls: ClientConfig,
    connect_timeout: std::time::Duration,
) -> Result<Channel> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("'{host}' is not a valid TLS server name"))?;
    let connector = TlsConnector::from(Arc::new(tls));
    let addr = format!("{host}:{port}");
    let uri: Uri = format!("https://{addr}")
        .parse()
        .with_context(|| format!("gateway address '{addr}' does not form a valid URL"))?;

    let host_owned = host.to_string();
    let channel = Endpoint::from(uri)
        .connect_timeout(connect_timeout)
        .tcp_nodelay(true)
        .http2_keep_alive_interval(std::time::Duration::from_secs(25))
        .keep_alive_timeout(std::time::Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let connector = connector.clone();
            let server_name = server_name.clone();
            let addr = addr.clone();
            let host = host_owned.clone();
            async move {
                // Resolve, connect and handshake as separate steps so a
                // failure names its stage — getaddrinfo in particular can
                // surface raw errnos (EAI_SYSTEM) that are meaningless
                // without the "this was DNS" context.
                let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&addr)
                    .await
                    .map_err(|e| {
                        std::io::Error::new(
                            e.kind(),
                            format!("resolving gateway host '{host}' failed: {e}"),
                        )
                    })?
                    .collect();
                if addrs.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("gateway host '{host}' resolved to no addresses"),
                    ));
                }
                let tcp = TcpStream::connect(&addrs[..]).await.map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!("TCP connect to {host} ({addrs:?}) failed: {e}"),
                    )
                })?;
                connector.connect(server_name, tcp).await.map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!("TLS handshake with '{host}' failed: {e}"),
                    )
                })
            }
        }))
        .await?;
    Ok(channel)
}

#[cfg_attr(not(test), allow(dead_code))] // the mock-enrollment tests' pin helper
pub fn sha256_fingerprint(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ca_pem() -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn pinned_root_store_builder() {
        let ca = test_ca_pem();
        // Pinned store: exactly the given anchors; empty input is an error
        // (a control channel with no trust anchors must not silently
        // connect-and-fail-open).
        let pinned = pinned_roots(&[&ca]).unwrap();
        assert_eq!(pinned.len(), 1);
        assert!(pinned_roots(&[]).is_err());
        assert!(pinned_roots(&["not a pem"]).is_err());
    }
}
