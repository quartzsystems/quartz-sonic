//! Daemon orchestration: identity assurance and the control-channel task.
//!
//! The daemon is deliberately restart-cheap and stateless: `enroll` writes
//! the durable state and try-restarts the unit; everything durable lives
//! under /var/lib/quartz-sonic/.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use crate::control::{ControlChannel, StatusCell};
use crate::identity::IdentityStore;
use crate::state::{self, ControlState, EnrollmentState, StatusDoc};

pub fn run() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    rt.block_on(run_async())
}

async fn run_async() -> Result<()> {
    tracing::info!("quartz-sonic {} starting", crate::VERSION);

    let store = IdentityStore::new(state::identity_dir());
    // First start (or pre-enrollment): create the identity so `status` and
    // the console can already show the device ID.
    let identity = store.load_or_generate()?;
    let device_id = identity.key.device_id();
    let st = EnrollmentState::load(&state::state_file())?;

    let status = StatusCell::new(
        StatusDoc {
            time_unix: state::now_unix(),
            enrolled: st.enrolled,
            device_id: Some(device_id.clone()),
            org_id: st.org_id.clone(),
            gateway: st.control_gateway(),
            cert_not_after_unix: st.cert_not_after_unix,
            renew_after_unix: st.renew_after_unix,
            cert_renewal_alarm: false,
            control: if st.enrolled { ControlState::Connecting } else { ControlState::Unenrolled },
            control_since_unix: None,
            last_error: None,
        },
        state::status_file(),
    );
    status.update(|_| {}).await; // initial write

    if !st.enrolled {
        tracing::info!(
            %device_id,
            "not enrolled — run 'quartz-sonic enroll '<TOKEN>'' with a token from the \
             QuartzCommand console"
        );
        park(status).await;
        return Ok(());
    }

    tracing::info!(%device_id, gateway = ?st.control_gateway(), "enrolled — starting control channel");
    let control = ControlChannel { store, status: status.clone() };
    tokio::select! {
        res = control.run(&identity, st) => {
            if let Err(e) = res {
                tracing::error!("control channel stopped: {e:#}");
                status.update(|d| {
                    d.control = ControlState::Backoff;
                    d.last_error = Some(format!("{e:#}"));
                }).await;
                park(status).await;
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("shutting down");
        }
    }
    Ok(())
}

/// Idle keeping status.json fresh until terminated (unenrolled /
/// unrecoverable states — `enroll` restarts the unit to pick up changes).
async fn park(status: Arc<StatusCell>) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                status.update(|_| {}).await;
            }
            _ = shutdown_signal() => return,
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
