//! sFlow for the console's Configure → Switching → sFlow page.
//!
//! Backed by CONFIG_DB `SFLOW|global` (admin_state, polling_interval,
//! agent_id), `SFLOW_COLLECTOR|<name>` (collector_ip, collector_port,
//! collector_vrf — SONiC allows at most two rows), and `SFLOW_SESSION|<port>`
//! (admin_state, sample_rate), all consumed by hsflowd in the sflow
//! container. A port with no session row follows the `SFLOW_SESSION|all`
//! row when present, else SONiC's default of enabled-at-speed-based-rate.
//!
//! Capability: supported when the sflow FEATURE exists; read_only (state
//! shown, writes refused) while the sflow docker isn't running.

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, field, key_suffix, keys, row, Platform};
use super::switching::{natural_cmp, oper_status_of, parse_num, WriteError, WriteResult};
use super::{APPL_DB, CONFIG_DB, STATE_DB};

const UNSUPPORTED: &str = "the sflow feature is not present on this image";
const DOCKER_DOWN: &str =
    "the sflow container is not running — enable the sflow feature to edit sFlow settings";

/// SONiC caps SFLOW_COLLECTOR at two rows.
const MAX_COLLECTORS: usize = 2;

fn capability(p: &probe::Probe) -> Capability {
    if !p.sflow_present() {
        Capability::no(UNSUPPORTED)
    } else if !p.docker_running("sflow") {
        Capability { supported: true, read_only: true, reason: Some(DOCKER_DOWN.into()) }
    } else {
        Capability::yes()
    }
}

#[derive(Debug, Serialize)]
struct CollectorDoc {
    name: String,
    address: String,
    port: Option<u64>,
    vrf: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct PortDoc {
    name: String,
    alias: Option<String>,
    oper_status: &'static str,
    enabled: bool,
    sample_rate: Option<u64>,
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    let cap = capability(&p);
    if !cap.supported {
        return Ok(json!({
            "capability": cap,
            "enabled": false,
            "polling_interval": null,
            "agent_id": null,
            "collectors": [],
            "ports": [],
        }));
    }

    let global = row(plat, CONFIG_DB, "SFLOW|global");
    let mut collectors = Vec::new();
    for key in keys(plat, CONFIG_DB, "SFLOW_COLLECTOR|*") {
        let Some(name) = key_suffix(&key, "SFLOW_COLLECTOR|") else { continue };
        let r = row(plat, CONFIG_DB, &key);
        collectors.push(CollectorDoc {
            name: name.to_string(),
            address: field(&r, "collector_ip").unwrap_or_default().to_string(),
            port: parse_num(field(&r, "collector_port")),
            vrf: match field(&r, "collector_vrf") {
                Some("mgmt") => Some("mgmt"),
                Some("default") => Some("default"),
                _ => None,
            },
        });
    }
    collectors.sort_by(|a, b| a.name.cmp(&b.name));

    // Ports without their own session row follow the "all" row, else the
    // image default (enabled, speed-based rate).
    let all_session = row(plat, CONFIG_DB, "SFLOW_SESSION|all");
    let all_enabled = field(&all_session, "admin_state").map(|s| s == "up");
    let all_rate = parse_num(field(&all_session, "sample_rate"));
    let mut names: Vec<String> = keys(plat, CONFIG_DB, "PORT|*")
        .iter()
        .filter_map(|k| key_suffix(k, "PORT|"))
        .map(str::to_string)
        .collect();
    names.sort_by(|a, b| natural_cmp(a, b));
    let mut ports = Vec::with_capacity(names.len());
    for name in names {
        let cfg = row(plat, CONFIG_DB, &format!("PORT|{name}"));
        let appl = row(plat, APPL_DB, &format!("PORT_TABLE:{name}"));
        let state = row(plat, STATE_DB, &format!("PORT_TABLE|{name}"));
        let session = row(plat, CONFIG_DB, &format!("SFLOW_SESSION|{name}"));
        let oper_status = match oper_status_of(&appl, &state).as_str() {
            "up" => "up",
            "down" => "down",
            _ => "unknown",
        };
        ports.push(PortDoc {
            alias: field(&cfg, "alias").map(str::to_string),
            oper_status,
            enabled: field(&session, "admin_state")
                .map(|s| s == "up")
                .or(all_enabled)
                .unwrap_or(true),
            sample_rate: parse_num(field(&session, "sample_rate")).or(all_rate),
            name,
        });
    }

    Ok(json!({
        "capability": cap,
        "enabled": field(&global, "admin_state") == Some("up"),
        "polling_interval": parse_num(field(&global, "polling_interval")),
        "agent_id": field(&global, "agent_id"),
        "collectors": collectors,
        "ports": ports,
    }))
}

// ── writes ──────────────────────────────────────────────────────────────────

fn check_writable(plat: &mut dyn Platform) -> WriteResult {
    let p = probe::current(plat);
    let cap = capability(&p);
    if !cap.supported {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    if cap.read_only {
        return Err(WriteError::Conflict(DOCKER_DOWN.to_string()));
    }
    Ok(())
}

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CollectorVrf {
    Default,
    Mgmt,
}

impl CollectorVrf {
    fn as_str(self) -> &'static str {
        match self {
            CollectorVrf::Default => "default",
            CollectorVrf::Mgmt => "mgmt",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CollectorInput {
    pub name: String,
    pub address: String,
    pub port: Option<u16>,
    pub vrf: Option<CollectorVrf>,
}

/// `PUT /api/switching/sflow` — global settings plus the full desired
/// collector set.
#[derive(Debug, Deserialize)]
pub struct GlobalInput {
    pub enabled: bool,
    pub polling_interval: Option<u64>,
    pub agent_id: Option<String>,
    #[serde(default)]
    pub collectors: Vec<CollectorInput>,
}

pub fn put_global(plat: &mut dyn Platform, input: &GlobalInput) -> WriteResult {
    let _lock = store::feature_lock("sflow");
    if let Some(v) = input.polling_interval {
        // hsflowd's accepted range; 0 turns counter polling off.
        if v != 0 && !(5..=300).contains(&v) {
            return Err(bad(format!(
                "invalid polling_interval {v} (must be 0 or 5-300 seconds)"
            )));
        }
    }
    if let Some(a) = &input.agent_id {
        if a.is_empty() || a.contains('|') || a.contains(char::is_whitespace) {
            return Err(bad(format!("invalid agent_id {a:?} (expected an interface name)")));
        }
    }
    if input.collectors.len() > MAX_COLLECTORS {
        return Err(bad(format!(
            "SONiC allows at most {MAX_COLLECTORS} sFlow collectors ({} given)",
            input.collectors.len()
        )));
    }
    let mut names = Vec::new();
    for c in &input.collectors {
        if c.name.is_empty() || c.name.contains('|') || c.name.contains(char::is_whitespace) {
            return Err(bad(format!("invalid collector name {:?}", c.name)));
        }
        if names.contains(&&c.name) {
            return Err(bad(format!("duplicate collector name {}", c.name)));
        }
        names.push(&c.name);
        if c.address.parse::<std::net::IpAddr>().is_err() {
            return Err(bad(format!(
                "invalid collector address {:?} (expected an IP address)",
                c.address
            )));
        }
        if c.port == Some(0) {
            return Err(bad("collector port must be 1-65535".to_string()));
        }
    }
    check_writable(plat)?;

    let global = "SFLOW|global";
    plat.hset(
        CONFIG_DB,
        global,
        &[("admin_state", if input.enabled { "up" } else { "down" })],
    )?;
    match input.polling_interval {
        Some(v) => plat.hset(CONFIG_DB, global, &[("polling_interval", &v.to_string())])?,
        None => plat.hdel(CONFIG_DB, global, &["polling_interval"])?,
    }
    match &input.agent_id {
        Some(a) => plat.hset(CONFIG_DB, global, &[("agent_id", a.as_str())])?,
        None => plat.hdel(CONFIG_DB, global, &["agent_id"])?,
    }

    // Converge SFLOW_COLLECTOR to the desired set.
    for key in plat.scan(CONFIG_DB, "SFLOW_COLLECTOR|*")? {
        let stale = key_suffix(&key, "SFLOW_COLLECTOR|")
            .is_none_or(|name| !input.collectors.iter().any(|c| c.name == name));
        if stale {
            plat.del(CONFIG_DB, &key)?;
        }
    }
    for c in &input.collectors {
        let key = format!("SFLOW_COLLECTOR|{}", c.name);
        plat.hset(CONFIG_DB, &key, &[("collector_ip", c.address.as_str())])?;
        match c.port {
            Some(v) => plat.hset(CONFIG_DB, &key, &[("collector_port", &v.to_string())])?,
            None => plat.hdel(CONFIG_DB, &key, &["collector_port"])?,
        }
        match c.vrf {
            Some(v) => plat.hset(CONFIG_DB, &key, &[("collector_vrf", v.as_str())])?,
            None => plat.hdel(CONFIG_DB, &key, &["collector_vrf"])?,
        }
    }
    Ok(())
}

/// `PUT /api/switching/sflow/ports/{name}`.
#[derive(Debug, Deserialize)]
pub struct PortInput {
    pub enabled: bool,
    pub sample_rate: Option<u64>,
}

pub fn put_port(plat: &mut dyn Platform, name: &str, input: &PortInput) -> WriteResult {
    let _lock = store::feature_lock("sflow");
    if let Some(v) = input.sample_rate {
        if !(256..=8_388_608).contains(&v) {
            return Err(bad(format!("invalid sample_rate {v} (must be 256-8388608)")));
        }
    }
    check_writable(plat)?;
    if !plat.exists(CONFIG_DB, &format!("PORT|{name}"))? {
        return Err(WriteError::NotFound(format!("no such port {name}")));
    }

    let key = format!("SFLOW_SESSION|{name}");
    plat.hset(
        CONFIG_DB,
        &key,
        &[("admin_state", if input.enabled { "up" } else { "down" })],
    )?;
    match input.sample_rate {
        Some(v) => plat.hset(CONFIG_DB, &key, &[("sample_rate", &v.to_string())])?,
        None => plat.hdel(CONFIG_DB, &key, &["sample_rate"])?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::store::{mem::MemPlatform, CmdOutput};
    use super::*;

    fn platform(docker_running: bool) -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        m.seed(CONFIG_DB, "FEATURE|sflow", &[("state", "enabled")]);
        m.seed(CONFIG_DB, "PORT|Ethernet0", &[("alias", "Eth1/1")]);
        m.seed(CONFIG_DB, "PORT|Ethernet4", &[("alias", "Eth1/2")]);
        if docker_running {
            m.on_cmd(
                &["docker", "ps"],
                CmdOutput { ok: true, stdout: "sflow\nswss\n".into(), stderr: String::new() },
            );
        }
        m
    }

    fn global_input(collectors: Vec<CollectorInput>) -> GlobalInput {
        GlobalInput {
            enabled: true,
            polling_interval: Some(20),
            agent_id: Some("Loopback0".into()),
            collectors,
        }
    }

    fn collector(name: &str, address: &str) -> CollectorInput {
        CollectorInput { name: name.into(), address: address.into(), port: None, vrf: None }
    }

    #[test]
    fn missing_feature_is_unsupported() {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        m.seed(CONFIG_DB, "PORT|Ethernet0", &[]);
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        assert_eq!(doc["ports"], json!([]));
        assert!(matches!(
            put_global(&mut m, &global_input(vec![])).unwrap_err(),
            WriteError::Conflict(_)
        ));
    }

    #[test]
    fn stopped_docker_is_read_only() {
        let mut m = platform(false);
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["capability"]["read_only"], true);
        assert_eq!(doc["capability"]["reason"], DOCKER_DOWN);
        // State still shows, writes are refused.
        assert_eq!(doc["ports"].as_array().unwrap().len(), 2);
        let err = put_port(
            &mut m,
            "Ethernet0",
            &PortInput { enabled: false, sample_rate: None },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
    }

    #[test]
    fn get_reports_globals_collectors_and_port_defaults() {
        let mut m = platform(true);
        m.seed(
            CONFIG_DB,
            "SFLOW|global",
            &[("admin_state", "up"), ("polling_interval", "30"), ("agent_id", "Loopback0")],
        );
        m.seed(
            CONFIG_DB,
            "SFLOW_COLLECTOR|collector0",
            &[("collector_ip", "10.0.0.50"), ("collector_port", "6344"), ("collector_vrf", "mgmt")],
        );
        m.seed(CONFIG_DB, "SFLOW_SESSION|all", &[("admin_state", "down")]);
        m.seed(
            CONFIG_DB,
            "SFLOW_SESSION|Ethernet0",
            &[("admin_state", "up"), ("sample_rate", "4096")],
        );
        m.seed(APPL_DB, "PORT_TABLE:Ethernet0", &[("oper_status", "up")]);
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["enabled"], true);
        assert_eq!(doc["polling_interval"], 30);
        assert_eq!(doc["agent_id"], "Loopback0");
        let collectors = doc["collectors"].as_array().unwrap();
        assert_eq!(collectors.len(), 1);
        assert_eq!(collectors[0]["name"], "collector0");
        assert_eq!(collectors[0]["address"], "10.0.0.50");
        assert_eq!(collectors[0]["port"], 6344);
        assert_eq!(collectors[0]["vrf"], "mgmt");
        let ports = doc["ports"].as_array().unwrap();
        // Ethernet0 has its own session row.
        assert_eq!(ports[0]["name"], "Ethernet0");
        assert_eq!(ports[0]["oper_status"], "up");
        assert_eq!(ports[0]["enabled"], true);
        assert_eq!(ports[0]["sample_rate"], 4096);
        // Ethernet4 follows the "all" row (disabled) with no rate override.
        assert_eq!(ports[1]["name"], "Ethernet4");
        assert_eq!(ports[1]["oper_status"], "unknown");
        assert_eq!(ports[1]["enabled"], false);
        assert_eq!(ports[1]["sample_rate"], serde_json::Value::Null);
    }

    #[test]
    fn global_put_writes_and_converges_collectors() {
        let mut m = platform(true);
        m.seed(CONFIG_DB, "SFLOW_COLLECTOR|old", &[("collector_ip", "10.9.9.9")]);
        let mut c0 = collector("collector0", "10.0.0.50");
        c0.port = Some(6344);
        c0.vrf = Some(CollectorVrf::Mgmt);
        put_global(&mut m, &global_input(vec![c0, collector("collector1", "fc00::9")]))
            .unwrap();
        let global = m.row(CONFIG_DB, "SFLOW|global");
        assert_eq!(global.get("admin_state").unwrap(), "up");
        assert_eq!(global.get("polling_interval").unwrap(), "20");
        assert_eq!(global.get("agent_id").unwrap(), "Loopback0");
        // The stale collector is gone; the desired two exist.
        assert!(!m.has_key(CONFIG_DB, "SFLOW_COLLECTOR|old"));
        let c0 = m.row(CONFIG_DB, "SFLOW_COLLECTOR|collector0");
        assert_eq!(c0.get("collector_ip").unwrap(), "10.0.0.50");
        assert_eq!(c0.get("collector_port").unwrap(), "6344");
        assert_eq!(c0.get("collector_vrf").unwrap(), "mgmt");
        let c1 = m.row(CONFIG_DB, "SFLOW_COLLECTOR|collector1");
        assert_eq!(c1.get("collector_ip").unwrap(), "fc00::9");
        assert!(!c1.contains_key("collector_port"));
        // Nulls clear the global tunables.
        put_global(
            &mut m,
            &GlobalInput { enabled: false, polling_interval: None, agent_id: None, collectors: vec![] },
        )
        .unwrap();
        let global = m.row(CONFIG_DB, "SFLOW|global");
        assert_eq!(global.get("admin_state").unwrap(), "down");
        assert!(!global.contains_key("polling_interval"));
        assert!(!global.contains_key("agent_id"));
        assert!(!m.has_key(CONFIG_DB, "SFLOW_COLLECTOR|collector0"));
    }

    #[test]
    fn global_put_enforces_the_two_collector_maximum() {
        let mut m = platform(true);
        let err = put_global(
            &mut m,
            &global_input(vec![
                collector("c0", "10.0.0.1"),
                collector("c1", "10.0.0.2"),
                collector("c2", "10.0.0.3"),
            ]),
        )
        .unwrap_err();
        match err {
            WriteError::BadRequest(msg) => assert!(msg.contains("at most 2"), "{msg}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
        assert!(!m.has_key(CONFIG_DB, "SFLOW|global"));
    }

    #[test]
    fn global_put_validates_values() {
        let mut m = platform(true);
        let mut bad_interval = global_input(vec![]);
        bad_interval.polling_interval = Some(3);
        assert!(matches!(
            put_global(&mut m, &bad_interval).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        assert!(matches!(
            put_global(&mut m, &global_input(vec![collector("c0", "not-an-ip")])).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        assert!(matches!(
            put_global(
                &mut m,
                &global_input(vec![collector("c0", "10.0.0.1"), collector("c0", "10.0.0.2")]),
            )
            .unwrap_err(),
            WriteError::BadRequest(_)
        ));
    }

    #[test]
    fn port_put_writes_session_rows() {
        let mut m = platform(true);
        put_port(&mut m, "Ethernet0", &PortInput { enabled: false, sample_rate: Some(8192) })
            .unwrap();
        let row = m.row(CONFIG_DB, "SFLOW_SESSION|Ethernet0");
        assert_eq!(row.get("admin_state").unwrap(), "down");
        assert_eq!(row.get("sample_rate").unwrap(), "8192");
        // null removes the rate override, keeping the admin state.
        put_port(&mut m, "Ethernet0", &PortInput { enabled: true, sample_rate: None }).unwrap();
        let row = m.row(CONFIG_DB, "SFLOW_SESSION|Ethernet0");
        assert_eq!(row.get("admin_state").unwrap(), "up");
        assert!(!row.contains_key("sample_rate"));
        assert!(matches!(
            put_port(&mut m, "Ethernet0", &PortInput { enabled: true, sample_rate: Some(100) })
                .unwrap_err(),
            WriteError::BadRequest(_)
        ));
        assert!(matches!(
            put_port(&mut m, "Ethernet99", &PortInput { enabled: true, sample_rate: None })
                .unwrap_err(),
            WriteError::NotFound(_)
        ));
    }
}
