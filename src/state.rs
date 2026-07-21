//! Persistent enrollment state and the live status contract.
//!
//! * `/var/lib/quartz-sonic/state.json` — enrollment outcome (device ID, org,
//!   gateways, cert validity). Written by `enroll` and by the renewal loop.
//! * `/run/quartz-sonic/status.json` — live status for `quartz-sonic status`
//!   (atomic replace, world-readable).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::identity::atomic_write;

pub const STATE_ROOT: &str = "/var/lib/quartz-sonic";
pub const RUN_DIR: &str = "/run/quartz-sonic";

pub fn state_file() -> PathBuf {
    PathBuf::from(STATE_ROOT).join("state.json")
}
pub fn identity_dir() -> PathBuf {
    PathBuf::from(STATE_ROOT)
}
pub fn status_file() -> PathBuf {
    PathBuf::from(RUN_DIR).join("status.json")
}

/// Durable enrollment state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnrollmentState {
    pub enrolled: bool,
    pub device_id: Option<String>,
    pub org_id: Option<String>,
    /// host:port from the consumed token.
    pub token_gateway: Option<String>,
    /// host:port assigned by the controller (preferred when non-empty).
    pub assigned_gateway: Option<String>,
    /// SHA-256 hex of the consumed token string (diagnostics).
    pub last_token_sha256: Option<String>,
    pub enrolled_at_unix: Option<i64>,
    pub cert_not_before_unix: Option<i64>,
    pub cert_not_after_unix: Option<i64>,
    /// Renew at/after this time (server value when the renewal RPC supplied
    /// one, else 2/3 of the cert lifetime).
    pub renew_after_unix: Option<i64>,
}

impl EnrollmentState {
    /// The gateway the control channel should dial: controller-assigned,
    /// falling back to the token's.
    pub fn control_gateway(&self) -> Option<String> {
        self.assigned_gateway
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| self.token_gateway.clone())
    }

    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("parse {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        atomic_write(path, serde_json::to_string_pretty(self)?.as_bytes())
    }
}

// ── live status ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlState {
    Unenrolled,
    Connecting,
    Connected,
    Backoff,
}

/// The status.json document. Everything `quartz-sonic status` shows that is
/// live (not durable state) comes from here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusDoc {
    pub time_unix: i64,
    pub enrolled: bool,
    pub device_id: Option<String>,
    pub org_id: Option<String>,
    /// Gateway the control channel uses (assigned, else token's).
    pub gateway: Option<String>,
    pub cert_not_after_unix: Option<i64>,
    pub renew_after_unix: Option<i64>,
    /// Set when the cert expires in under 7 days and renewal has not
    /// succeeded.
    pub cert_renewal_alarm: bool,
    pub control: ControlState,
    pub control_since_unix: Option<i64>,
    pub last_error: Option<String>,
}

impl StatusDoc {
    pub fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        atomic_write(path, serde_json::to_vec_pretty(self)?.as_slice())
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_state_roundtrip_and_gateway_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        // Missing file → default (unenrolled).
        let st = EnrollmentState::load(&path).unwrap();
        assert!(!st.enrolled);
        assert_eq!(st.control_gateway(), None);

        let st = EnrollmentState {
            enrolled: true,
            token_gateway: Some("token.example:443".into()),
            assigned_gateway: Some("assigned.example:7443".into()),
            ..Default::default()
        };
        st.save(&path).unwrap();
        let loaded = EnrollmentState::load(&path).unwrap();
        assert!(loaded.enrolled);
        // Controller-assigned gateway wins…
        assert_eq!(loaded.control_gateway().as_deref(), Some("assigned.example:7443"));
        // …but an EMPTY assigned gateway falls back to the token's.
        let fallback = EnrollmentState { assigned_gateway: Some(String::new()), ..loaded };
        assert_eq!(fallback.control_gateway().as_deref(), Some("token.example:443"));
    }

    #[test]
    fn status_doc_writes_readable_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        let doc = StatusDoc {
            time_unix: 1,
            enrolled: false,
            device_id: Some("QS-TEST".into()),
            org_id: None,
            gateway: None,
            cert_not_after_unix: None,
            renew_after_unix: None,
            cert_renewal_alarm: false,
            control: ControlState::Unenrolled,
            control_since_unix: None,
            last_error: None,
        };
        doc.write(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["control"], "unenrolled");
        assert_eq!(v["device_id"], "QS-TEST");
    }
}
