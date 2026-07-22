//! The local management API the controller's ProxyRequests are routed to.
//!
//! Unlike QuartzFire (which fronts a separate local web UI over loopback
//! HTTP), quartz-sonic answers the console's `/api/…` calls inside the agent
//! itself: SONiC has no bundled management backend to proxy to, and keeping
//! the surface in-process means one less listener on the switch.
//!
//! Endpoints (start minimal; grow as the console grows):
//!   GET    /api/system/info                    — SONiC version, platform, HWSKU, serial, …
//!   GET    /api/system/health                  — resource gauges + redis reachability
//!   POST   /api/system/reboot                  — graceful reboot via SONiC's `reboot` script
//!   GET    /api/switching/ports                — port inventory: status, VLANs, error counters
//!   PUT    /api/switching/ports/{name}         — patch port config + VLAN membership
//!   GET    /api/switching/port-channels        — LAGs with per-member state
//!   POST   /api/switching/port-channels        — create a LAG
//!   PUT    /api/switching/port-channels/{name} — converge a LAG's fields + members
//!   DELETE /api/switching/port-channels/{name} — remove a LAG
//!   GET    /api/switching/vlans                — VLANs with members and L3 config
//!   POST   /api/switching/vlans                — create a VLAN
//!   PUT    /api/switching/vlans/{id}           — converge a VLAN's fields + sets
//!   DELETE /api/switching/vlans/{id}           — remove a VLAN and its rows
//!
//! Writes go to CONFIG_DB and are persisted with `config save -y`
//! (best-effort). Unknown paths get a 404-style ProxyResponse with `error`
//! set; a bad request must never crash the stream.

use serde_json::json;

use crate::sonic;
use crate::sonic::switching::{self, WriteError};

/// A ProxyResponse body-tuple: (http_status, content_type, body, error).
pub type CallResult = (u32, String, Vec<u8>, String);

const JSON: &str = "application/json";

pub struct Api {
    pub agent_version: String,
    pub device_id: String,
}

/// Routing decision, separated from execution for testability.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    SystemInfo,
    SystemHealth,
    SystemReboot,
    SwitchingPorts,
    PortUpdate(String),
    SwitchingPortChannels,
    PortChannelCreate,
    PortChannelUpdate(String),
    PortChannelDelete(String),
    SwitchingVlans,
    VlanCreate,
    VlanUpdate(u32),
    VlanDelete(u32),
    NotFound,
    MethodNotAllowed { allowed: &'static str },
}

/// Match a method + path (query string ignored) to a route.
fn route(method: &str, path: &str) -> Route {
    let path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    match path {
        "/api/system/info" => match method {
            "GET" => Route::SystemInfo,
            _ => Route::MethodNotAllowed { allowed: "GET" },
        },
        "/api/system/health" => match method {
            "GET" => Route::SystemHealth,
            _ => Route::MethodNotAllowed { allowed: "GET" },
        },
        "/api/system/reboot" => match method {
            "POST" => Route::SystemReboot,
            _ => Route::MethodNotAllowed { allowed: "POST" },
        },
        "/api/switching/ports" => match method {
            "GET" => Route::SwitchingPorts,
            _ => Route::MethodNotAllowed { allowed: "GET" },
        },
        "/api/switching/port-channels" => match method {
            "GET" => Route::SwitchingPortChannels,
            "POST" => Route::PortChannelCreate,
            _ => Route::MethodNotAllowed { allowed: "GET, POST" },
        },
        "/api/switching/vlans" => match method {
            "GET" => Route::SwitchingVlans,
            "POST" => Route::VlanCreate,
            _ => Route::MethodNotAllowed { allowed: "GET, POST" },
        },
        _ => route_item(method, path),
    }
}

/// Routes with a trailing `{name}` / `{vlan_id}` path segment.
fn route_item(method: &str, path: &str) -> Route {
    if let Some(name) = item_name(path, "/api/switching/ports/") {
        return match method {
            "PUT" => Route::PortUpdate(name.to_string()),
            _ => Route::MethodNotAllowed { allowed: "PUT" },
        };
    }
    if let Some(name) = item_name(path, "/api/switching/port-channels/") {
        return match method {
            "PUT" => Route::PortChannelUpdate(name.to_string()),
            "DELETE" => Route::PortChannelDelete(name.to_string()),
            _ => Route::MethodNotAllowed { allowed: "PUT, DELETE" },
        };
    }
    if let Some(id) = item_name(path, "/api/switching/vlans/") {
        // A non-numeric id can't name a VLAN — 404, not 405.
        let Ok(id) = id.parse::<u32>() else { return Route::NotFound };
        return match method {
            "PUT" => Route::VlanUpdate(id),
            "DELETE" => Route::VlanDelete(id),
            _ => Route::MethodNotAllowed { allowed: "PUT, DELETE" },
        };
    }
    Route::NotFound
}

/// The single path segment after `prefix`; None when absent, empty, or nested.
fn item_name<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.strip_prefix(prefix).filter(|s| !s.is_empty() && !s.contains('/'))
}

impl Api {
    pub fn new(agent_version: String, device_id: String) -> Self {
        Self { agent_version, device_id }
    }

    /// Serve one proxied call. Never panics; every outcome is a well-formed
    /// ProxyResponse tuple.
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        _content_type: &str,
        body: Vec<u8>,
    ) -> CallResult {
        match route(method, path) {
            Route::SystemInfo => {
                let agent_version = self.agent_version.clone();
                let device_id = self.device_id.clone();
                run_blocking(move || system_info(&agent_version, &device_id)).await
            }
            Route::SystemHealth => run_blocking(system_health).await,
            Route::SystemReboot => reboot(),
            Route::SwitchingPorts => run_blocking(switching_ports).await,
            Route::SwitchingPortChannels => run_blocking(switching_port_channels).await,
            Route::SwitchingVlans => run_blocking(switching_vlans).await,
            Route::PortUpdate(name) => {
                run_blocking(move || {
                    with_body(&body, |p: &switching::PortPatch| switching::update_port(&name, p))
                })
                .await
            }
            Route::VlanCreate => {
                run_blocking(move || {
                    with_body(&body, |c: &switching::VlanCreate| {
                        switching::create_vlan(c.vlan_id, &c.input)
                    })
                })
                .await
            }
            Route::VlanUpdate(id) => {
                run_blocking(move || {
                    with_body(&body, |i: &switching::VlanInput| switching::update_vlan(id, i))
                })
                .await
            }
            Route::VlanDelete(id) => {
                run_blocking(move || write_outcome(switching::delete_vlan(id))).await
            }
            Route::PortChannelCreate => {
                run_blocking(move || {
                    with_body(&body, |c: &switching::PortChannelCreate| {
                        switching::create_port_channel(&c.name, &c.input)
                    })
                })
                .await
            }
            Route::PortChannelUpdate(name) => {
                run_blocking(move || {
                    with_body(&body, |i: &switching::PortChannelInput| {
                        switching::update_port_channel(&name, i)
                    })
                })
                .await
            }
            Route::PortChannelDelete(name) => {
                run_blocking(move || write_outcome(switching::delete_port_channel(&name))).await
            }
            Route::NotFound => (
                404,
                JSON.to_string(),
                json_body(&json!({ "error": "not found" })),
                format!("no such endpoint: {method} {path}"),
            ),
            Route::MethodNotAllowed { allowed } => (
                405,
                JSON.to_string(),
                json_body(&json!({ "error": "method not allowed", "allowed": allowed })),
                format!("method {method} not allowed on {path} (use {allowed})"),
            ),
        }
    }
}

/// Collectors read /proc and redis — off the async runtime they go.
async fn run_blocking(f: impl FnOnce() -> CallResult + Send + 'static) -> CallResult {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) => (
            0,
            String::new(),
            Vec::new(),
            format!("local handler panicked or was cancelled: {e}"),
        ),
    }
}

fn json_body(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

fn system_info(agent_version: &str, device_id: &str) -> CallResult {
    let facts = sonic::system_facts();
    let stats = super::stats::collect();
    // The console types these as string|null — an undetermined fact must
    // arrive as null, not "".
    let opt = |s: String| if s.is_empty() { serde_json::Value::Null } else { s.into() };
    let body = json!({
        "device_id": device_id,
        "hostname": facts.hostname,
        "sonic_version": opt(facts.sonic_version),
        "platform": opt(facts.platform),
        "hwsku": opt(facts.hwsku),
        "serial": opt(facts.serial),
        "uptime_secs": stats.uptime_secs,
        "agent_version": agent_version,
    });
    (200, JSON.to_string(), json_body(&body), String::new())
}

fn system_health() -> CallResult {
    let redis_ok = sonic::redis_ok();
    let stats = super::stats::collect();
    let body = json!({
        "status": if redis_ok { "ok" } else { "degraded" },
        "redis": redis_ok,
        "cpu_pct": stats.cpu_pct,
        "mem_pct": stats.mem_pct,
        "disk_pct": stats.disk_pct,
        "mem_used_bytes": stats.mem_used_bytes,
        "mem_total_bytes": stats.mem_total_bytes,
        "disk_used_bytes": stats.disk_used_bytes,
        "disk_total_bytes": stats.disk_total_bytes,
        "uptime_secs": stats.uptime_secs,
    });
    (200, JSON.to_string(), json_body(&body), String::new())
}

fn switching_ports() -> CallResult {
    match sonic::switching::ports() {
        Ok(ports) => (200, JSON.to_string(), json_body(&json!({ "ports": ports })), String::new()),
        Err(e) => redis_unreachable(&e),
    }
}

fn switching_port_channels() -> CallResult {
    match sonic::switching::port_channels() {
        Ok(pcs) => (
            200,
            JSON.to_string(),
            json_body(&json!({ "port_channels": pcs })),
            String::new(),
        ),
        Err(e) => redis_unreachable(&e),
    }
}

fn switching_vlans() -> CallResult {
    match sonic::switching::vlans() {
        Ok(vlans) => (200, JSON.to_string(), json_body(&json!({ "vlans": vlans })), String::new()),
        Err(e) => redis_unreachable(&e),
    }
}

/// CONFIG_DB itself was unreachable — the one condition the switching
/// endpoints are allowed to fail on (anything less degrades to the contract's
/// nulls/defaults inside the collectors).
fn redis_unreachable(e: &anyhow::Error) -> CallResult {
    let msg = format!("SONiC redis unreachable: {e:#}");
    (500, JSON.to_string(), json_body(&json!({ "error": msg })), msg)
}

/// Parse a write body and hand it to `op`; an unparsable body is a 400
/// before redis is ever touched.
fn with_body<T, F>(body: &[u8], op: F) -> CallResult
where
    T: serde::de::DeserializeOwned,
    F: FnOnce(&T) -> Result<(), WriteError>,
{
    match switching::parse_json::<T>(body) {
        Ok(v) => write_outcome(op(&v)),
        Err(msg) => error_response(400, msg),
    }
}

/// Map a write op's outcome to the contract: 200 {"ok": true} (after a
/// best-effort `config save -y`), 400/404/422 with {"error": …}, or the
/// readers' 500 shape when redis itself failed.
fn write_outcome(r: Result<(), WriteError>) -> CallResult {
    match r {
        Ok(()) => {
            persist_config();
            (200, JSON.to_string(), json_body(&json!({ "ok": true })), String::new())
        }
        Err(WriteError::BadRequest(msg)) => error_response(400, msg),
        Err(WriteError::NotFound(msg)) => error_response(404, msg),
        Err(WriteError::Unprocessable(msg)) => error_response(422, msg),
        Err(WriteError::Redis(e)) => redis_unreachable(&e),
    }
}

fn error_response(status: u32, msg: String) -> CallResult {
    (status, JSON.to_string(), json_body(&json!({ "error": msg })), msg)
}

/// Persist CONFIG_DB to /etc/sonic/config_db.json so the mutation survives a
/// reboot. Best-effort: the write already applied, so a failed save is logged
/// (and the next successful one will pick it up), never surfaced as an error.
fn persist_config() {
    match std::process::Command::new("config").args(["save", "-y"]).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => tracing::warn!(
            "config save -y failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => tracing::warn!("config save -y could not run: {e}"),
    }
}

/// Kick off SONiC's graceful `reboot` script (falls back to /sbin/reboot),
/// detached and delayed a few seconds so the 202 response reaches the
/// controller before the box goes down.
fn reboot() -> CallResult {
    tracing::warn!("reboot requested by the controller");
    let spawned = std::process::Command::new("sh")
        .args(["-c", "sleep 3; reboot || /sbin/reboot"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    match spawned {
        Ok(_) => (
            202,
            JSON.to_string(),
            json_body(&json!({ "status": "rebooting" })),
            String::new(),
        ),
        Err(e) => (
            500,
            JSON.to_string(),
            json_body(&json!({ "error": format!("failed to start reboot: {e}") })),
            format!("failed to start reboot: {e}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_known_endpoints() {
        assert_eq!(route("GET", "/api/system/info"), Route::SystemInfo);
        assert_eq!(route("GET", "/api/system/health"), Route::SystemHealth);
        assert_eq!(route("POST", "/api/system/reboot"), Route::SystemReboot);
        // Query strings and trailing slashes don't change the route.
        assert_eq!(route("GET", "/api/system/info?verbose=1"), Route::SystemInfo);
        assert_eq!(route("GET", "/api/system/info/"), Route::SystemInfo);
    }

    #[test]
    fn routes_switching_endpoints() {
        assert_eq!(route("GET", "/api/switching/ports"), Route::SwitchingPorts);
        assert_eq!(
            route("GET", "/api/switching/port-channels"),
            Route::SwitchingPortChannels
        );
        assert_eq!(route("GET", "/api/switching/vlans"), Route::SwitchingVlans);
    }

    #[test]
    fn collection_paths_share_get_and_post() {
        assert_eq!(route("POST", "/api/switching/vlans"), Route::VlanCreate);
        assert_eq!(route("POST", "/api/switching/port-channels"), Route::PortChannelCreate);
        assert_eq!(
            route("DELETE", "/api/switching/vlans"),
            Route::MethodNotAllowed { allowed: "GET, POST" }
        );
        // Ports has no create — the collection stays GET-only.
        assert_eq!(
            route("POST", "/api/switching/ports"),
            Route::MethodNotAllowed { allowed: "GET" }
        );
    }

    #[test]
    fn routes_item_write_endpoints() {
        assert_eq!(
            route("PUT", "/api/switching/ports/Ethernet0"),
            Route::PortUpdate("Ethernet0".into())
        );
        assert_eq!(
            route("GET", "/api/switching/ports/Ethernet0"),
            Route::MethodNotAllowed { allowed: "PUT" }
        );
        assert_eq!(route("PUT", "/api/switching/vlans/10"), Route::VlanUpdate(10));
        assert_eq!(route("DELETE", "/api/switching/vlans/10"), Route::VlanDelete(10));
        assert_eq!(
            route("POST", "/api/switching/vlans/10"),
            Route::MethodNotAllowed { allowed: "PUT, DELETE" }
        );
        assert_eq!(
            route("PUT", "/api/switching/port-channels/PortChannel0001"),
            Route::PortChannelUpdate("PortChannel0001".into())
        );
        assert_eq!(
            route("DELETE", "/api/switching/port-channels/PortChannel0001"),
            Route::PortChannelDelete("PortChannel0001".into())
        );
        // Query strings and trailing slashes don't change item routes either.
        assert_eq!(
            route("PUT", "/api/switching/ports/Ethernet0/?dry=1"),
            Route::PortUpdate("Ethernet0".into())
        );
    }

    #[test]
    fn malformed_item_paths_are_not_found() {
        // A non-numeric VLAN id can't name a VLAN.
        assert_eq!(route("PUT", "/api/switching/vlans/abc"), Route::NotFound);
        assert_eq!(route("PUT", "/api/switching/vlans/-1"), Route::NotFound);
        // Nested segments aren't item names.
        assert_eq!(route("PUT", "/api/switching/ports/a/b"), Route::NotFound);
    }

    #[test]
    fn wrong_method_is_405_not_404() {
        assert_eq!(
            route("POST", "/api/system/info"),
            Route::MethodNotAllowed { allowed: "GET" }
        );
        assert_eq!(
            route("GET", "/api/system/reboot"),
            Route::MethodNotAllowed { allowed: "POST" }
        );
    }

    #[test]
    fn unknown_paths_fall_through_to_not_found() {
        assert_eq!(route("GET", "/api/nope"), Route::NotFound);
        assert_eq!(route("GET", "/etc/passwd"), Route::NotFound);
        assert_eq!(route("DELETE", "/"), Route::NotFound);
        assert_eq!(route("GET", ""), Route::NotFound);
    }

    /// The full call path for an unknown endpoint: 404, JSON body, error set,
    /// and — critically — no panic.
    #[tokio::test]
    async fn unknown_endpoint_yields_404_with_error() {
        let api = Api::new("test".into(), "QS-TEST".into());
        let (status, ct, body, error) = api.call("GET", "/api/does/not/exist", "", vec![]).await;
        assert_eq!(status, 404);
        assert_eq!(ct, "application/json");
        assert!(!error.is_empty());
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "not found");
    }

    #[tokio::test]
    async fn wrong_method_yields_405_with_error() {
        let api = Api::new("test".into(), "QS-TEST".into());
        let (status, _, _, error) = api.call("DELETE", "/api/system/reboot", "", vec![]).await;
        assert_eq!(status, 405);
        assert!(error.contains("use POST"), "{error}");
    }

    /// Body parsing happens before any redis access, so a bad payload is a
    /// deterministic 400 regardless of the environment.
    #[tokio::test]
    async fn unparsable_write_bodies_yield_400() {
        let api = Api::new("test".into(), "QS-TEST".into());
        for (method, path, body) in [
            ("PUT", "/api/switching/ports/Ethernet0", &b"{not json"[..]),
            ("PUT", "/api/switching/ports/Ethernet0", br#"{"admin_status":"sideways"}"#),
            ("POST", "/api/switching/vlans", br#"{"description":"missing vlan_id"}"#),
            ("POST", "/api/switching/port-channels", br#"{"name":"PortChannel1"}"#),
            ("PUT", "/api/switching/port-channels/PortChannel1", br#"{"protocol":"pagp"}"#),
        ] {
            let (status, ct, body, error) =
                api.call(method, path, "application/json", body.to_vec()).await;
            assert_eq!(status, 400, "{method} {path}: {error}");
            assert_eq!(ct, "application/json");
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(v["error"].as_str().unwrap().starts_with("invalid body:"), "{v}");
            assert!(!error.is_empty());
        }
    }

    /// Pure payload validation also precedes redis: an out-of-range VLAN id
    /// or a bad LAG name is a 400 even with no CONFIG_DB around.
    #[tokio::test]
    async fn invalid_payload_values_yield_400() {
        let api = Api::new("test".into(), "QS-TEST".into());
        let (status, _, body, _) = api
            .call("POST", "/api/switching/vlans", JSON, br#"{"vlan_id": 4095}"#.to_vec())
            .await;
        assert_eq!(status, 400);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"].as_str().unwrap().contains("invalid VLAN id"), "{v}");

        let pc = br#"{"name":"Po1","protocol":"lacp","admin_status":"up",
                      "fallback":false,"fast_rate":false,"members":[]}"#;
        let (status, _, body, _) =
            api.call("POST", "/api/switching/port-channels", JSON, pc.to_vec()).await;
        assert_eq!(status, 400);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"].as_str().unwrap().contains("invalid port channel name"), "{v}");

        let patch = br#"{"vlan_mode":"access","untagged_vlan":null}"#;
        let (status, _, body, _) = api
            .call("PUT", "/api/switching/ports/Ethernet0", JSON, patch.to_vec())
            .await;
        assert_eq!(status, 400);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"].as_str().unwrap().contains("requires untagged_vlan"), "{v}");
    }
}
