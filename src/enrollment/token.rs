//! Enrollment token parsing.
//!
//! Wire format (authoritative, controller-issued):
//!
//! ```text
//! QC1|<gateway_host:port>|<org_id>|<token_id>.<secret>|sha256:<hex_ca_fingerprint>
//! ```
//!
//! Parsing is strict: every malformed segment is rejected with an error
//! naming that segment, so a mangled copy-paste fails with a message the
//! operator can act on. The parsed [`EnrollToken`] never prints its secret
//! (`Debug` redacts it) — the raw token string must not be logged.

use sha2::{Digest, Sha256};

/// A parsed enrollment token.
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollToken {
    pub gateway_host: String,
    pub gateway_port: u16,
    pub org_id: String,
    pub token_id: String,
    pub secret: String,
    /// SHA-256 of the controller's issuing device-CA certificate (DER) — the
    /// trust anchor for the bootstrap TLS connection.
    pub ca_fingerprint: [u8; 32],
    /// SHA-256 of the full token string (idempotency/diagnostics key).
    pub sha256_hex: String,
}

impl std::fmt::Debug for EnrollToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollToken")
            .field("gateway_host", &self.gateway_host)
            .field("gateway_port", &self.gateway_port)
            .field("org_id", &self.org_id)
            .field("token_id", &self.token_id)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl EnrollToken {
    pub fn gateway(&self) -> String {
        format!("{}:{}", self.gateway_host, self.gateway_port)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("enrollment token is too long ({0} bytes; limit 1024)")]
    TooLong(usize),
    #[error("enrollment token contains whitespace or control characters — paste it as a single unbroken line (quote it: quartz-sonic enroll '<TOKEN>')")]
    BadCharacters,
    #[error("enrollment token must have 5 '|'-separated segments (version|gateway|org|token|ca-fingerprint), found {0}")]
    SegmentCount(usize),
    #[error("segment 1 (version) must be 'QC1', found '{0}' — this agent only understands QC1 tokens")]
    Version(String),
    #[error("segment 2 (gateway) must be host:port, found '{0}'")]
    GatewayShape(String),
    #[error("segment 2 (gateway) has an invalid port '{0}' (expected 1-65535)")]
    GatewayPort(String),
    #[error("segment 3 (org id) is empty")]
    OrgEmpty,
    #[error("segment 4 (token) must be <token_id>.<secret> with both parts non-empty")]
    TokenShape,
    #[error("segment 5 (CA fingerprint) must start with 'sha256:'")]
    FingerprintScheme,
    #[error("segment 5 (CA fingerprint) must be 64 hex characters after 'sha256:', found {0}")]
    FingerprintHex(usize),
}

/// Parse a token string, strictly.
pub fn parse(raw: &str) -> Result<EnrollToken, TokenError> {
    if raw.len() > 1024 {
        return Err(TokenError::TooLong(raw.len()));
    }
    // Reject embedded whitespace/control bytes and non-ASCII outright: every
    // legitimate token is a single printable-ASCII line, and anything else is
    // a mangled paste (or hostile input) better refused than half-parsed.
    if !raw.chars().all(|c| c.is_ascii_graphic()) {
        return Err(TokenError::BadCharacters);
    }

    let segments: Vec<&str> = raw.split('|').collect();
    if segments.len() != 5 {
        return Err(TokenError::SegmentCount(segments.len()));
    }

    if segments[0] != "QC1" {
        return Err(TokenError::Version(segments[0].to_string()));
    }

    // Gateway host:port. IPv6 literals use the usual [addr]:port form.
    let (host_raw, port_raw) = segments[1]
        .rsplit_once(':')
        .ok_or_else(|| TokenError::GatewayShape(segments[1].to_string()))?;
    let host = host_raw
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host_raw);
    if host.is_empty() || host.contains('|') {
        return Err(TokenError::GatewayShape(segments[1].to_string()));
    }
    let port: u16 = match port_raw.parse::<u16>() {
        Ok(p) if p >= 1 => p,
        _ => return Err(TokenError::GatewayPort(port_raw.to_string())),
    };

    let org_id = segments[2];
    if org_id.is_empty() {
        return Err(TokenError::OrgEmpty);
    }

    let (token_id, secret) = segments[3].split_once('.').ok_or(TokenError::TokenShape)?;
    if token_id.is_empty() || secret.is_empty() {
        return Err(TokenError::TokenShape);
    }

    let fp_hex = segments[4]
        .strip_prefix("sha256:")
        .ok_or(TokenError::FingerprintScheme)?;
    if fp_hex.len() != 64 || !fp_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(TokenError::FingerprintHex(fp_hex.len()));
    }
    let mut ca_fingerprint = [0u8; 32];
    for (i, byte) in ca_fingerprint.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&fp_hex[2 * i..2 * i + 2], 16).expect("checked hex");
    }

    Ok(EnrollToken {
        gateway_host: host.to_string(),
        gateway_port: port,
        org_id: org_id.to_string(),
        token_id: token_id.to_string(),
        secret: secret.to_string(),
        ca_fingerprint,
        sha256_hex: hex(&Sha256::digest(raw.as_bytes())),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "sha256:aa00000000000000000000000000000000000000000000000000000000000bb1";

    fn valid() -> String {
        format!("QC1|gw.example.com:8443|org_1234|tok_abc.s3cr3tS3cr3t|{FP}")
    }

    #[test]
    fn parses_valid_token() {
        let t = parse(&valid()).unwrap();
        assert_eq!(t.gateway_host, "gw.example.com");
        assert_eq!(t.gateway_port, 8443);
        assert_eq!(t.gateway(), "gw.example.com:8443");
        assert_eq!(t.org_id, "org_1234");
        assert_eq!(t.token_id, "tok_abc");
        assert_eq!(t.secret, "s3cr3tS3cr3t");
        assert_eq!(t.ca_fingerprint[0], 0xaa);
        assert_eq!(t.ca_fingerprint[31], 0xb1);
        assert_eq!(t.sha256_hex.len(), 64);
    }

    #[test]
    fn parses_ipv6_gateway() {
        let t = parse(&format!("QC1|[2001:db8::1]:443|org|id.sec|{FP}")).unwrap();
        assert_eq!(t.gateway_host, "2001:db8::1");
        assert_eq!(t.gateway_port, 443);
    }

    #[test]
    fn rejects_wrong_segment_count() {
        assert_eq!(parse("QC1|a:1|org|id.sec"), Err(TokenError::SegmentCount(4)));
        assert_eq!(
            parse(&format!("{}|extra", valid())),
            Err(TokenError::SegmentCount(6))
        );
    }

    #[test]
    fn rejects_bad_version() {
        let raw = valid().replace("QC1|", "QC2|");
        assert_eq!(parse(&raw), Err(TokenError::Version("QC2".into())));
    }

    #[test]
    fn rejects_bad_gateway() {
        assert_eq!(
            parse(&format!("QC1|noport|org|id.sec|{FP}")),
            Err(TokenError::GatewayShape("noport".into()))
        );
        assert_eq!(
            parse(&format!("QC1|:443|org|id.sec|{FP}")),
            Err(TokenError::GatewayShape(":443".into()))
        );
        assert_eq!(
            parse(&format!("QC1|gw:0|org|id.sec|{FP}")),
            Err(TokenError::GatewayPort("0".into()))
        );
        assert_eq!(
            parse(&format!("QC1|gw:99999|org|id.sec|{FP}")),
            Err(TokenError::GatewayPort("99999".into()))
        );
        assert_eq!(
            parse(&format!("QC1|gw:https|org|id.sec|{FP}")),
            Err(TokenError::GatewayPort("https".into()))
        );
    }

    #[test]
    fn rejects_empty_org() {
        assert_eq!(
            parse(&format!("QC1|gw:443||id.sec|{FP}")),
            Err(TokenError::OrgEmpty)
        );
    }

    #[test]
    fn rejects_bad_token_segment() {
        assert_eq!(
            parse(&format!("QC1|gw:443|org|nodot|{FP}")),
            Err(TokenError::TokenShape)
        );
        assert_eq!(
            parse(&format!("QC1|gw:443|org|.seconly|{FP}")),
            Err(TokenError::TokenShape)
        );
        assert_eq!(
            parse(&format!("QC1|gw:443|org|idonly.|{FP}")),
            Err(TokenError::TokenShape)
        );
    }

    #[test]
    fn rejects_bad_fingerprint() {
        assert_eq!(
            parse("QC1|gw:443|org|id.sec|md5:aabb"),
            Err(TokenError::FingerprintScheme)
        );
        assert_eq!(
            parse("QC1|gw:443|org|id.sec|sha256:aabb"),
            Err(TokenError::FingerprintHex(4))
        );
        let bad_hex = format!("sha256:{}", "zz".repeat(32));
        assert_eq!(
            parse(&format!("QC1|gw:443|org|id.sec|{bad_hex}")),
            Err(TokenError::FingerprintHex(64))
        );
    }

    #[test]
    fn rejects_hostile_input() {
        assert_eq!(parse(""), Err(TokenError::SegmentCount(1)));
        assert_eq!(parse("QC1|gw:443|org|id.sec|x\ny"), Err(TokenError::BadCharacters));
        assert_eq!(parse("QC1 |gw:443|org|id.sec|x"), Err(TokenError::BadCharacters));
        assert_eq!(parse("QC1|gw:443|org|id.sec|\u{0000}"), Err(TokenError::BadCharacters));
        assert_eq!(parse("QC1|gw:443|órg|id.sec|x"), Err(TokenError::BadCharacters));
        let huge = format!("QC1|gw:443|org|id.{}|{FP}", "a".repeat(2000));
        assert!(matches!(parse(&huge), Err(TokenError::TooLong(_))));
    }

    #[test]
    fn debug_redacts_secret() {
        let dbg = format!("{:?}", parse(&valid()).unwrap());
        assert!(!dbg.contains("s3cr3tS3cr3t"), "secret leaked in Debug: {dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    /// The idempotency hash covers the whole raw string.
    #[test]
    fn hash_differs_across_tokens() {
        let a = parse(&valid()).unwrap();
        let b = parse(&valid().replace("tok_abc", "tok_xyz")).unwrap();
        assert_ne!(a.sha256_hex, b.sha256_hex);
    }
}
