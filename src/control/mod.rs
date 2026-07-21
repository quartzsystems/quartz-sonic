//! The persistent control channel to the assigned QuartzCommand gateway:
//! certificate renewal plus the ControlStream command channel.
//!
//! The connection is established eagerly with 25 s keepalive pings; connect
//! failures back off exponentially with jitter (1 s → 5 min cap). Once up,
//! `connected_wait()` opens the bidirectional ControlStream, announces the
//! device with a DeviceHello, and then serves the controller's ProxyRequests
//! (routed to the in-process management API, see `mgmtapi`) while also
//! driving renewal — a completed renewal returns so the caller reconnects
//! with the new cert. The controller closing the stream means "reconnect".

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;

use crate::enrollment as enroll;
use crate::identity::{Identity, IdentityStore};
use crate::sonic::mgmtapi::Api;

pub mod daemon;
pub mod tls;
use crate::proto::device::device_service_client::DeviceServiceClient;
use crate::proto::device::{
    controller_message, device_message, DeviceHello, DeviceMessage, ProxyResponse,
    RenewCertificateRequest,
};
use crate::state::{self, ControlState, EnrollmentState, StatusDoc};

/// Shared, serialized view of the live status; every mutation is written
/// through to status.json.
pub struct StatusCell {
    doc: Mutex<StatusDoc>,
    path: std::path::PathBuf,
}

impl StatusCell {
    pub fn new(doc: StatusDoc, path: std::path::PathBuf) -> Arc<Self> {
        Arc::new(Self { doc: Mutex::new(doc), path })
    }

    pub async fn update(&self, f: impl FnOnce(&mut StatusDoc)) {
        let mut doc = self.doc.lock().await;
        f(&mut doc);
        doc.time_unix = state::now_unix();
        if let Err(e) = doc.write(&self.path) {
            tracing::warn!("writing {} failed: {e:#}", self.path.display());
        }
    }
}

/// Full jitter without a rand dependency: the subsecond clock is plenty for
/// decorrelating a fleet's reconnect storms.
fn jitter(max: Duration) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    Duration::from_millis(nanos % (max.as_millis().max(1) as u64))
}

pub struct ControlChannel {
    pub store: IdentityStore,
    pub status: Arc<StatusCell>,
}

impl ControlChannel {
    /// Reconnect-forever loop. Returns only on unrecoverable local state
    /// (missing cert files) — the daemon then parks in an error state.
    pub async fn run(&self, identity: &Identity, mut st: EnrollmentState) -> Result<()> {
        let mut backoff = Duration::from_secs(1);
        loop {
            let gateway = st
                .control_gateway()
                .context("enrolled but no gateway recorded — re-enroll")?;
            let (host, port) = split_gateway(&gateway)?;

            self.status
                .update(|d| {
                    d.control = ControlState::Connecting;
                    d.gateway = Some(gateway.clone());
                })
                .await;

            match self.connect(&host, port).await {
                Ok(channel) => {
                    tracing::info!(%gateway, "control channel established");
                    backoff = Duration::from_secs(1);
                    self.status
                        .update(|d| {
                            d.control = ControlState::Connected;
                            d.control_since_unix = Some(state::now_unix());
                            d.last_error = None;
                        })
                        .await;

                    match self.connected_wait(channel, identity, &mut st).await {
                        Ok(()) => continue, // renewed → reconnect with the new cert
                        Err(e) => {
                            tracing::warn!("control channel lost: {e:#}");
                            self.status
                                .update(|d| {
                                    d.control = ControlState::Backoff;
                                    d.control_since_unix = None;
                                    d.last_error = Some(format!("{e:#}"));
                                })
                                .await;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(%gateway, "control channel connect failed: {e:#}");
                    self.status
                        .update(|d| {
                            d.control = ControlState::Backoff;
                            d.last_error = Some(format!("{e:#}"));
                        })
                        .await;
                }
            }

            let wait = backoff + jitter(backoff);
            tracing::debug!("reconnecting in {wait:?}");
            tokio::time::sleep(wait).await;
            backoff = (backoff * 2).min(Duration::from_secs(300));
        }
    }

    async fn connect(&self, host: &str, port: u16) -> Result<tonic::transport::Channel> {
        let client_cert = std::fs::read_to_string(self.store.client_cert_path())
            .context("read client.crt — the device may not be enrolled (run 'quartz-sonic enroll')")?;
        let key_pem = std::fs::read_to_string(self.store.key_path()).context("read device.key")?;
        let chain: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut client_cert.as_bytes())
                .collect::<std::result::Result<_, _>>()
                .context("parse client.crt")?;
        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut key_pem.as_bytes())
                .context("parse device.key")?
                .context("device.key holds no key")?;

        // Server trust: the device-CA chain persisted at enrollment (verified
        // then against the token's fingerprint), plus the exact pinned CA.
        let ca_chain = std::fs::read_to_string(self.store.ca_chain_path()).unwrap_or_default();
        let pinned = std::fs::read_to_string(self.store.pinned_ca_path()).unwrap_or_default();
        let mut pems: Vec<&str> = Vec::new();
        if !pinned.is_empty() {
            pems.push(&pinned);
        }
        pems.push(&ca_chain);
        let roots = tls::pinned_roots(&pems)?;
        let (tls_config, _outcome) = tls::client_config(roots, None, Some((chain, key)))?;
        tls::grpc_channel(host, port, tls_config, Duration::from_secs(15)).await
    }

    /// Hold the connection doing useful work: serve the controller's
    /// ProxyRequests over the ControlStream, push DeviceStats (~30 s) and
    /// SecurityTelemetry (~60 s), and when certificate renewal is due, run
    /// it, persist, and return Ok(()) so the caller reconnects with the
    /// fresh cert. Any stream failure is a lost channel (Err → backoff).
    async fn connected_wait(
        &self,
        channel: tonic::transport::Channel,
        identity: &Identity,
        st: &mut EnrollmentState,
    ) -> Result<()> {
        // Open the command channel and announce ourselves. The mpsc sender is
        // cloned into each in-flight request handler; the stream ends when
        // every sender is dropped or the server closes its half.
        let mut client = DeviceServiceClient::new(channel.clone());
        let (tx, rx) = tokio::sync::mpsc::channel::<DeviceMessage>(16);
        tx.send(DeviceMessage {
            msg: Some(device_message::Msg::Hello(DeviceHello {
                hostname: crate::sonic::read_hostname(),
                qf_version: crate::VERSION.to_string(),
            })),
        })
        .await
        .ok();
        let mut inbound = client
            .control_stream(ReceiverStream::new(rx))
            .await
            .map_err(|s| {
                anyhow::anyhow!("ControlStream failed ({:?}): {}", s.code(), s.message())
            })?
            .into_inner();
        let local = Arc::new(Api::new(
            crate::VERSION.to_string(),
            st.device_id.clone().unwrap_or_else(|| identity.key.device_id()),
        ));

        // Push snapshots up the same stream on fixed cadences. The first tick
        // of each interval fires immediately, so the controller gets fresh
        // data right after the DeviceHello. Collection is offloaded to
        // blocking tasks (it samples /proc and reads redis) and the send is
        // best-effort — a closed channel (stream gone) just drops the
        // snapshot, and the stream arms below detect the disconnect.
        let mut stats_tick = tokio::time::interval(crate::sonic::stats::INTERVAL);
        let mut telemetry_tick = tokio::time::interval(crate::sonic::telemetry::INTERVAL);

        loop {
            let now = state::now_unix();
            let renew_at = st.renew_after_unix.unwrap_or(now);
            let alarm = st
                .cert_not_after_unix
                .is_some_and(|exp| exp - now < 7 * 86_400);
            self.status.update(|d| d.cert_renewal_alarm = alarm && now >= renew_at).await;

            if now < renew_at {
                // Serve the stream until the next renewal re-check (at least
                // hourly so the alarm flag stays fresh).
                let wait = ((renew_at - now).min(3600)).max(1) as u64;
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
                    _ = stats_tick.tick() => {
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            match tokio::task::spawn_blocking(crate::sonic::stats::collect).await {
                                Ok(snapshot) => {
                                    let _ = tx
                                        .send(DeviceMessage {
                                            msg: Some(device_message::Msg::DeviceStats(snapshot)),
                                        })
                                        .await;
                                }
                                Err(e) => tracing::warn!("device-stats collection task failed: {e}"),
                            }
                        });
                    }
                    _ = telemetry_tick.tick() => {
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            match tokio::task::spawn_blocking(crate::sonic::telemetry::collect).await {
                                Ok(snapshot) => {
                                    let _ = tx
                                        .send(DeviceMessage {
                                            msg: Some(device_message::Msg::SecurityTelemetry(
                                                snapshot,
                                            )),
                                        })
                                        .await;
                                }
                                Err(e) => tracing::warn!("telemetry collection task failed: {e}"),
                            }
                        });
                    }
                    msg = inbound.message() => match msg {
                        Ok(Some(m)) => {
                            if let Some(controller_message::Msg::ProxyRequest(req)) = m.msg {
                                let local = local.clone();
                                let tx = tx.clone();
                                tokio::spawn(async move {
                                    let (http_status, content_type, body, error) = local
                                        .call(
                                            &req.method,
                                            &req.path,
                                            &req.content_type,
                                            req.body,
                                        )
                                        .await;
                                    let _ = tx
                                        .send(DeviceMessage {
                                            msg: Some(device_message::Msg::ProxyResponse(
                                                ProxyResponse {
                                                    request_id: req.request_id,
                                                    http_status,
                                                    content_type,
                                                    body,
                                                    error,
                                                },
                                            )),
                                        })
                                        .await;
                                });
                            }
                        }
                        Ok(None) => anyhow::bail!("control stream closed by the controller"),
                        Err(s) => anyhow::bail!(
                            "control stream error ({:?}): {}",
                            s.code(),
                            s.message()
                        ),
                    },
                }
                continue;
            }

            tracing::info!("certificate renewal due — requesting a fresh certificate");
            let device_id = st.device_id.clone().context("no device id in state")?;
            let csr_der = enroll::build_csr(&identity.key, &device_id)?;
            let mut client = DeviceServiceClient::new(channel.clone());
            let resp = client
                .renew_certificate(RenewCertificateRequest { csr_der })
                .await
                .map_err(|s| {
                    anyhow::anyhow!("RenewCertificate failed ({:?}): {}", s.code(), s.message())
                })?
                .into_inner();
            if resp.client_cert_der.is_empty() {
                anyhow::bail!("controller returned an empty renewed certificate");
            }

            // Keep the existing pinned CA (trust anchor rotation is a
            // re-enrollment event, not a renewal one); save_certificates
            // swaps every file atomically.
            self.store.save_certificates(&resp.client_cert_der, &resp.ca_chain_der, None)?;

            let (not_before, not_after) = enroll::cert_validity(&resp.client_cert_der)?;
            st.cert_not_before_unix = Some(not_before);
            st.cert_not_after_unix =
                Some(if resp.not_after_unix > 0 { resp.not_after_unix } else { not_after });
            st.renew_after_unix = Some(if resp.renew_after_unix > 0 {
                resp.renew_after_unix
            } else {
                enroll::renew_after(not_before, not_after)
            });
            st.save(&state::state_file())?;
            self.status
                .update(|d| {
                    d.cert_not_after_unix = st.cert_not_after_unix;
                    d.renew_after_unix = st.renew_after_unix;
                    d.cert_renewal_alarm = false;
                })
                .await;
            tracing::info!(
                not_after = st.cert_not_after_unix,
                "certificate renewed — reconnecting with the new certificate"
            );
            return Ok(());
        }
    }
}

fn split_gateway(gateway: &str) -> Result<(String, u16)> {
    let (host_raw, port) = gateway
        .rsplit_once(':')
        .with_context(|| format!("gateway '{gateway}' is not host:port"))?;
    let host = host_raw
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host_raw);
    Ok((host.to_string(), port.parse().with_context(|| format!("bad port in '{gateway}'"))?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_splitting() {
        assert_eq!(split_gateway("gw.example:443").unwrap(), ("gw.example".into(), 443));
        assert_eq!(split_gateway("[2001:db8::1]:7443").unwrap(), ("2001:db8::1".into(), 7443));
        assert!(split_gateway("noport").is_err());
        assert!(split_gateway("gw:badport").is_err());
    }
}
