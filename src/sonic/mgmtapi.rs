//! The local management API the controller's ProxyRequests are routed to.
//!
//! Unlike QuartzFire (which fronts a separate local web UI over loopback
//! HTTP), quartz-sonic answers the console's `/api/…` calls inside the agent
//! itself: SONiC has no bundled management backend to proxy to, and keeping
//! the surface in-process means one less listener on the switch.
//!
//! Endpoints (start minimal; grow as the console grows):
//!   GET  /api/system/info   — SONiC version, platform, HWSKU, serial, …
//!   GET  /api/system/health — resource gauges + redis reachability
//!   POST /api/system/reboot — graceful reboot via SONiC's `reboot` script
//!
//! Unknown paths get a 404-style ProxyResponse with `error` set; a bad
//! request must never crash the stream.

use serde_json::json;

use crate::sonic;

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
        _ => Route::NotFound,
    }
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
        _body: Vec<u8>,
    ) -> CallResult {
        match route(method, path) {
            Route::SystemInfo => {
                let agent_version = self.agent_version.clone();
                let device_id = self.device_id.clone();
                run_blocking(move || system_info(&agent_version, &device_id)).await
            }
            Route::SystemHealth => run_blocking(system_health).await,
            Route::SystemReboot => reboot(),
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
    let body = json!({
        "device_id": device_id,
        "hostname": facts.hostname,
        "sonic_version": facts.sonic_version,
        "platform": facts.platform,
        "hwsku": facts.hwsku,
        "serial": facts.serial,
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
}
