//! The CLI entry points other than the daemon itself:
//!
//!   enroll <TOKEN>  — one-shot enrollment against the token's gateway
//!   unenroll        — clear local enrollment (certs + state); console-side
//!                     revocation is still the operator's job
//!   status          — device ID, enrollment state, gateway, cert expiry,
//!                     stream connectivity

use std::path::Path;

use anyhow::{Context, Result};

use crate::enrollment::{self as enroll, token};
use crate::identity::IdentityStore;
use crate::state::{self, ControlState, EnrollmentState, StatusDoc};
use crate::{sonic, VERSION};

fn log(msg: &str) {
    eprintln!("quartz-sonic: {msg}");
}

// ── enroll ────────────────────────────────────────────────────────────────────

/// `quartz-sonic enroll '<TOKEN>'`. One attempt, no retry loop — the
/// enrollment endpoint is rate-limited per source IP, and a failed token
/// needs the operator anyway.
pub fn enroll_cmd(raw_token: &str, force: bool) -> i32 {
    match enroll_inner(raw_token, force) {
        Ok(()) => 0,
        Err(e) => {
            log(&format!("{e:#}"));
            1
        }
    }
}

fn enroll_inner(raw_token: &str, force: bool) -> Result<()> {
    let token = token::parse(raw_token.trim()).map_err(|e| anyhow::anyhow!("{e}"))?;

    let store = IdentityStore::new(state::identity_dir());
    let identity = store
        .load_or_generate()
        .context("create/load the device identity (are you running as root?)")?;
    let device_id = identity.key.device_id();

    let st = EnrollmentState::load(&state::state_file())?;
    if st.enrolled && !force {
        anyhow::bail!(
            "this switch is already enrolled as {} (org {}). An adopted device cannot \
             re-enroll until it is revoked in the QuartzCommand console; after revoking, \
             re-run with --force.",
            st.device_id.as_deref().unwrap_or(&device_id),
            st.org_id.as_deref().unwrap_or("?")
        );
    }

    log(&format!("device ID {device_id}"));
    log(&format!("enrolling against {} …", token.gateway()));

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let outcome = rt.block_on(enroll::enroll(
        &identity.key,
        enroll::EnrollRequest {
            token: &token,
            hostname: sonic::read_hostname(),
            agent_version: VERSION.to_string(),
        },
    ))?;

    store.save_certificates(
        &outcome.client_cert_der,
        &outcome.ca_chain_der,
        outcome.pinned_ca_der.as_deref(),
    )?;

    let new_state = EnrollmentState {
        enrolled: true,
        device_id: Some(outcome.device_id.clone()),
        org_id: Some(outcome.org_id.clone()),
        token_gateway: Some(token.gateway()),
        assigned_gateway: outcome.assigned_gateway.clone(),
        last_token_sha256: Some(token.sha256_hex.clone()),
        enrolled_at_unix: Some(state::now_unix()),
        cert_not_before_unix: Some(outcome.cert_not_before_unix),
        cert_not_after_unix: Some(outcome.cert_not_after_unix),
        renew_after_unix: Some(outcome.renew_after_unix),
    };
    new_state.save(&state::state_file())?;

    log(&format!(
        "enrolled as {} in org {} (gateway {})",
        outcome.device_id,
        outcome.org_id,
        new_state.control_gateway().as_deref().unwrap_or("?")
    ));

    // Pick the new state up in the daemon. Best-effort: on a box without the
    // unit installed/running this is a no-op and `run` can be started by hand.
    let restarted = std::process::Command::new("systemctl")
        .args(["try-restart", "quartz-sonic.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if restarted {
        log("quartz-sonic.service restarted — the control channel is connecting");
    } else {
        log("start the daemon to connect: systemctl restart quartz-sonic.service");
    }
    Ok(())
}

// ── unenroll ──────────────────────────────────────────────────────────────────

/// `quartz-sonic unenroll [--wipe-identity]`. Local-only: there is no
/// unenroll RPC in the fleet protocol, so this deletes the enrollment state
/// and certificates and restarts the daemon into its unenrolled park. The
/// issued client certificate stays valid until the operator revokes the
/// device in the QuartzCommand console.
pub fn unenroll_cmd(wipe_identity: bool) -> i32 {
    match unenroll_inner(wipe_identity) {
        Ok(()) => 0,
        Err(e) => {
            log(&format!("{e:#}"));
            1
        }
    }
}

fn unenroll_inner(wipe_identity: bool) -> Result<()> {
    let store = IdentityStore::new(state::identity_dir());
    let st = EnrollmentState::load(&state::state_file())?;

    if !st.enrolled && !wipe_identity {
        log("not enrolled — nothing to do");
        return Ok(());
    }
    if st.enrolled {
        log(&format!(
            "unenrolling {} (org {})",
            st.device_id.as_deref().unwrap_or("?"),
            st.org_id.as_deref().unwrap_or("?")
        ));
    }

    remove_enrollment_files(&store, &state::state_file(), wipe_identity)?;
    if wipe_identity {
        log("device identity wiped — the next enrollment gets a new device ID");
    }

    let restarted = std::process::Command::new("systemctl")
        .args(["try-restart", "quartz-sonic.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if restarted {
        log("quartz-sonic.service restarted — the switch is disconnected");
    }

    log(
        "local enrollment cleared. The controller was NOT notified: also \
         revoke/remove this device in the QuartzCommand console, or it stays \
         listed (offline) with a still-valid certificate.",
    );
    Ok(())
}

fn remove_enrollment_files(
    store: &IdentityStore,
    state_file: &Path,
    wipe_identity: bool,
) -> Result<()> {
    remove(state_file)?;
    remove(&store.client_cert_path())?;
    remove(&store.ca_chain_path())?;
    remove(&store.pinned_ca_path())?;
    if wipe_identity {
        remove(&store.key_path())?;
        remove(&store.pub_path())?;
    }
    Ok(())
}

fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e)
            .with_context(|| format!("remove {} (are you running as root?)", path.display())),
    }
}

// ── status ────────────────────────────────────────────────────────────────────

pub fn status(json: bool) -> i32 {
    let store = IdentityStore::new(state::identity_dir());
    let st = EnrollmentState::load(&state::state_file()).unwrap_or_default();
    let device_id = store
        .load()
        .ok()
        .map(|i| i.key.device_id())
        .or(st.device_id.clone());
    let live: Option<StatusDoc> = std::fs::read_to_string(state::status_file())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());

    if json {
        let doc = serde_json::json!({
            "agent_version": VERSION,
            "device_id": device_id,
            "enrolled": st.enrolled,
            "org_id": st.org_id,
            "gateway": st.control_gateway(),
            "cert_not_after_unix": st.cert_not_after_unix,
            "renew_after_unix": st.renew_after_unix,
            "live": live,
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
        return 0;
    }

    println!("quartz-sonic {VERSION}");
    println!("  device ID:   {}", device_id.as_deref().unwrap_or("(no identity yet — starts with the daemon)"));
    if st.enrolled {
        println!("  enrollment:  enrolled (org {})", st.org_id.as_deref().unwrap_or("?"));
        println!("  gateway:     {}", st.control_gateway().as_deref().unwrap_or("?"));
        match st.cert_not_after_unix {
            Some(exp) => {
                let days = (exp - state::now_unix()) / 86_400;
                println!("  cert expiry: {} ({} days)", format_unix(exp), days);
            }
            None => println!("  cert expiry: unknown"),
        }
        if let Some(renew) = st.renew_after_unix {
            println!("  renews:      at/after {}", format_unix(renew));
        }
    } else {
        println!("  enrollment:  not enrolled — run: sudo quartz-sonic enroll '<TOKEN>'");
    }
    match &live {
        Some(doc) => {
            let control = match doc.control {
                ControlState::Unenrolled => "unenrolled".to_string(),
                ControlState::Connecting => "connecting".to_string(),
                ControlState::Connected => match doc.control_since_unix {
                    Some(since) => format!("connected (since {})", format_unix(since)),
                    None => "connected".to_string(),
                },
                ControlState::Backoff => "reconnecting (backoff)".to_string(),
            };
            println!("  stream:      {control}");
            if doc.cert_renewal_alarm {
                println!("  ALARM:       certificate expires soon and renewal has not succeeded");
            }
            if let Some(err) = &doc.last_error {
                println!("  last error:  {err}");
            }
        }
        None => println!("  stream:      daemon not running (no status file)"),
    }
    0
}

/// Render a unix timestamp as UTC without a chrono dependency.
fn format_unix(unix: i64) -> String {
    // Days-since-epoch → civil date (Howard Hinnant's algorithm).
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unenroll_keeps_identity_unless_wiped() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path());
        store.load_or_generate().unwrap();
        store.save_certificates(b"cert", &[b"ca".to_vec()], Some(b"pin")).unwrap();
        let state_file = dir.path().join("state.json");
        EnrollmentState { enrolled: true, ..Default::default() }.save(&state_file).unwrap();

        remove_enrollment_files(&store, &state_file, false).unwrap();
        assert!(!state_file.exists());
        assert!(!store.client_cert_path().exists());
        assert!(!store.ca_chain_path().exists());
        assert!(!store.pinned_ca_path().exists());
        // Keypair survives: the device re-enrolls under the same device ID.
        assert!(store.key_path().exists());
        assert!(store.pub_path().exists());

        // Second run is a no-op, not an error; --wipe-identity takes the key.
        remove_enrollment_files(&store, &state_file, true).unwrap();
        assert!(!store.key_path().exists());
        assert!(!store.pub_path().exists());
    }

    #[test]
    fn unix_formatting() {
        assert_eq!(format_unix(0), "1970-01-01 00:00:00 UTC");
        // 2026-07-21 00:00:00 UTC
        assert_eq!(format_unix(1_784_592_000), "2026-07-21 00:00:00 UTC");
        // Leap-day handling.
        assert_eq!(format_unix(951_782_400), "2000-02-29 00:00:00 UTC");
    }
}
