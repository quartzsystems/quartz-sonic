//! Enrollment client tests against a mock EnrollmentService speaking the
//! real wire protocol over real TLS (in-crate — the crate is a binary, so
//! `tests/` can't import it).
//!
//! Covered: the happy path over the token CA-fingerprint pin, rejection when
//! the chain doesn't match the pin, uniform-rejection error mapping,
//! server-side verification of the nonce signature + CSR the client sends,
//! and the client's own verification of the returned CA chain against the
//! token fingerprint.
#![cfg(test)]

use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rustls::pki_types::PrivateKeyDer;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status};

use crate::enrollment::{self as enroll, token, EnrollRequest};
use crate::identity::deviceid;
use crate::identity::{IdentityStore, KeyBackend};
use crate::proto::enrollment::enrollment_service_server::{
    EnrollmentService, EnrollmentServiceServer,
};
use crate::proto::enrollment::{
    BeginEnrollmentRequest, BeginEnrollmentResponse, CompleteEnrollmentRequest,
    CompleteEnrollmentResponse,
};

const NONCE: &[u8] = b"mock-nonce-0123456789";
const SESSION: &str = "sess-1";
const SECRET: &str = "s3cr3tS3cr3t";

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Normal,
    ExpiredToken,
    RejectSignature,
    /// CompleteEnrollment returns a CA chain unrelated to the pinned CA —
    /// the client must refuse it.
    WrongChain,
}

struct MockCa {
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

struct MockService {
    mode: Mode,
    ca: Arc<MockCa>,
    assigned_gateway: String,
}

#[tonic::async_trait]
impl EnrollmentService for MockService {
    async fn begin_enrollment(
        &self,
        req: Request<BeginEnrollmentRequest>,
    ) -> Result<Response<BeginEnrollmentResponse>, Status> {
        let req = req.into_inner();
        if self.mode == Mode::ExpiredToken {
            // The real controller answers a dead token uniformly: NOT_FOUND
            // at begin.
            return Err(Status::not_found("enrollment failed"));
        }
        if req.token_id != "tok_1" {
            return Err(Status::not_found("unknown token id"));
        }
        if req.device_pubkey.len() != 32 {
            return Err(Status::invalid_argument("pubkey must be 32 bytes"));
        }
        Ok(Response::new(BeginEnrollmentResponse {
            nonce: NONCE.to_vec(),
            enrollment_session_id: SESSION.to_string(),
        }))
    }

    async fn complete_enrollment(
        &self,
        req: Request<CompleteEnrollmentRequest>,
    ) -> Result<Response<CompleteEnrollmentResponse>, Status> {
        let req = req.into_inner();
        if self.mode == Mode::RejectSignature {
            // Uniform rejection at complete: PERMISSION_DENIED.
            return Err(Status::permission_denied("enrollment failed"));
        }
        if req.enrollment_session_id != SESSION {
            return Err(Status::invalid_argument("unknown session"));
        }
        if req.token_secret != SECRET {
            return Err(Status::permission_denied("enrollment failed"));
        }

        // Verify the CSR carries an Ed25519 key and that the claimed device
        // id + nonce signature check out against it — the same checks the
        // real controller performs. The device id must carry the SONiC
        // product-line prefix.
        use x509_parser::prelude::FromDer as _;
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&req.csr_der)
                .map_err(|e| Status::invalid_argument(format!("bad CSR: {e}")))?;
        csr.verify_signature()
            .map_err(|e| Status::invalid_argument(format!("CSR self-signature invalid: {e}")))?;
        let spki = &csr.certification_request_info.subject_pki;
        let pubkey_raw: [u8; 32] = spki
            .subject_public_key
            .data
            .as_ref()
            .try_into()
            .map_err(|_| Status::invalid_argument("CSR key is not raw 32-byte Ed25519"))?;
        if !req.device_id.starts_with("QS-") {
            return Err(Status::invalid_argument("device_id must be a QS id"));
        }
        if deviceid::derive_device_id(&pubkey_raw) != req.device_id {
            return Err(Status::invalid_argument("device_id does not match CSR pubkey"));
        }
        let cn = csr
            .certification_request_info
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or_default();
        if cn != req.device_id {
            return Err(Status::invalid_argument("CSR CN must be the device id"));
        }
        let vk = VerifyingKey::from_bytes(&pubkey_raw)
            .map_err(|e| Status::invalid_argument(format!("bad pubkey: {e}")))?;
        let sig: Signature = Signature::from_slice(&req.nonce_signature)
            .map_err(|e| Status::invalid_argument(format!("bad signature shape: {e}")))?;
        vk.verify(NONCE, &sig)
            .map_err(|_| Status::invalid_argument("nonce signature verification failed"))?;

        // Issue a client cert from the CSR, CA-signed.
        let csr_params = rcgen::CertificateSigningRequestParams::from_der(
            &req.csr_der.clone().into(),
        )
        .map_err(|e| Status::internal(format!("rcgen CSR parse: {e}")))?;
        let issued = csr_params
            .signed_by(&self.ca.ca_cert, &self.ca.ca_key)
            .map_err(|e| Status::internal(format!("issue cert: {e}")))?;

        let ca_chain_der = if self.mode == Mode::WrongChain {
            // A syntactically valid CA that is NOT the pinned one.
            let other_key = rcgen::KeyPair::generate().unwrap();
            let mut other = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            other.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            vec![other.self_signed(&other_key).unwrap().der().to_vec()]
        } else {
            vec![self.ca.ca_cert.der().to_vec()]
        };

        Ok(Response::new(CompleteEnrollmentResponse {
            client_cert_der: issued.der().to_vec(),
            ca_chain_der,
            assigned_gateway: self.assigned_gateway.clone(),
            org_id: "org_test".to_string(),
        }))
    }
}

/// Newtype so a plain tokio-rustls stream satisfies tonic's `Connected`
/// bound (tonic only implements it for its own TLS types).
struct TestIo(tokio_rustls::server::TlsStream<tokio::net::TcpStream>);

impl Connected for TestIo {
    type ConnectInfo = ();
    fn connect_info(&self) {}
}

impl tokio::io::AsyncRead for TestIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TestIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

struct MockServer {
    port: u16,
    ca_der: Vec<u8>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

/// Start a TLS EnrollmentService on 127.0.0.1: CA → server cert for
/// "localhost". Returns the CA (trust material for the tests) and the port.
async fn start_mock(mode: Mode, assigned_gateway: &str) -> MockServer {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "QuartzCommand Mock CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let server_key = rcgen::KeyPair::generate().unwrap();
    let server_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_cert.der().clone(), ca_cert.der().clone()],
            PrivateKeyDer::try_from(server_key.serialize_der()).unwrap(),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let ca_der = ca_cert.der().to_vec();
    let ca = Arc::new(MockCa { ca_cert, ca_key });

    let (conn_tx, conn_rx) = mpsc::channel::<Result<TestIo, std::io::Error>>(4);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            let tx = conn_tx.clone();
            tokio::spawn(async move {
                if let Ok(stream) = acceptor.accept(tcp).await {
                    let _ = tx.send(Ok(TestIo(stream))).await;
                }
            });
        }
    });

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let service = MockService { mode, ca, assigned_gateway: assigned_gateway.to_string() };
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(EnrollmentServiceServer::new(service))
            .serve_with_incoming_shutdown(ReceiverStream::new(conn_rx), async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    MockServer { port, ca_der, _shutdown: shutdown_tx }
}

fn make_token(port: u16, fingerprint: [u8; 32]) -> token::EnrollToken {
    let fp_hex: String = fingerprint.iter().map(|b| format!("{b:02x}")).collect();
    token::parse(&format!("QC1|localhost:{port}|org_test|tok_1.{SECRET}|sha256:{fp_hex}"))
        .unwrap()
}

fn test_identity() -> (tempfile::TempDir, crate::identity::Identity) {
    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::new(dir.path().join("identity"));
    let id = store.load_or_generate().unwrap();
    (dir, id)
}

fn req(tok: &token::EnrollToken) -> EnrollRequest<'_> {
    EnrollRequest {
        token: tok,
        hostname: "test-switch".into(),
        agent_version: "test".into(),
    }
}

#[tokio::test]
async fn happy_path_via_pinned_ca() {
    let server = start_mock(Mode::Normal, "assigned.example.net:7443").await;
    let (_d, identity) = test_identity();
    let tok = make_token(server.port, crate::control::tls::sha256_fingerprint(&server.ca_der));

    let out = enroll::enroll(&identity.key, req(&tok)).await.unwrap();
    assert_eq!(out.org_id, "org_test");
    assert_eq!(out.pinned_ca_der.as_deref(), Some(server.ca_der.as_slice()));
    assert_eq!(out.assigned_gateway.as_deref(), Some("assigned.example.net:7443"));
    assert_eq!(out.device_id, deviceid::derive_device_id(&identity.key.public_key_raw()));
    assert!(out.device_id.starts_with("QS-"));
    assert_eq!(out.ca_chain_der, vec![server.ca_der.clone()]);
    // Issued cert parses and the renewal point is inside the validity window.
    let (nb, na) = enroll::cert_validity(&out.client_cert_der).unwrap();
    assert!(nb < na);
    assert!(out.renew_after_unix > nb && out.renew_after_unix < na);
}

#[tokio::test]
async fn empty_assigned_gateway_falls_back_to_token() {
    let server = start_mock(Mode::Normal, "").await;
    let (_d, identity) = test_identity();
    let tok = make_token(server.port, crate::control::tls::sha256_fingerprint(&server.ca_der));

    let out = enroll::enroll(&identity.key, req(&tok)).await.unwrap();
    // Empty assigned gateway from the server → None; callers fall back to
    // the token's gateway (state::control_gateway).
    assert_eq!(out.assigned_gateway, None);
}

#[tokio::test]
async fn rejects_chain_not_matching_fingerprint() {
    let server = start_mock(Mode::Normal, "").await;
    let (_d, identity) = test_identity();
    // Wrong fingerprint → hard reject during the TLS handshake, before any
    // RPC (no public roots to fall back to — pin only).
    let tok = make_token(server.port, [0u8; 32]);

    let err = enroll::enroll(&identity.key, req(&tok)).await.unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("does not match the token's CA fingerprint"),
        "unexpected error: {text}"
    );
}

#[tokio::test]
async fn dead_token_maps_to_friendly_uniform_error() {
    let server = start_mock(Mode::ExpiredToken, "").await;
    let (_d, identity) = test_identity();
    let tok = make_token(server.port, crate::control::tls::sha256_fingerprint(&server.ca_der));

    let err = enroll::enroll(&identity.key, req(&tok)).await.unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("check the token"), "unexpected error: {text}");
}

#[tokio::test]
async fn uniform_rejection_at_complete_maps_the_same_way() {
    let server = start_mock(Mode::RejectSignature, "").await;
    let (_d, identity) = test_identity();
    let tok = make_token(server.port, crate::control::tls::sha256_fingerprint(&server.ca_der));

    let err = enroll::enroll(&identity.key, req(&tok)).await.unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("check the token"), "unexpected error: {text}");
}

#[tokio::test]
async fn refuses_returned_chain_that_does_not_match_the_pin() {
    let server = start_mock(Mode::WrongChain, "").await;
    let (_d, identity) = test_identity();
    let tok = make_token(server.port, crate::control::tls::sha256_fingerprint(&server.ca_der));

    let err = enroll::enroll(&identity.key, req(&tok)).await.unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("does not match the enrollment token's CA fingerprint"),
        "unexpected error: {text}"
    );
}
