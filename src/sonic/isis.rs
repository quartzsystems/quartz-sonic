//! IS-IS for the console's Configure → Routing → IS-IS page.
//!
//! Community SONiC does not even start isisd in the FRR container — nothing
//! manages or persists it — so support is gated on the probe actually seeing
//! isisd among vtysh's daemons (enterprise/custom images). Where it runs,
//! configuration goes through vtysh ("router isis <tag>", "net <NET>",
//! "is-type …", per-interface "ip router isis <tag>", "isis circuit-type/
//! metric/passive/network point-to-point"); state is read back by parsing
//! `show running-config` and `show isis neighbor json`.
//!
//! Persistence follows the routing-config-mode rules: `vtysh -c "write
//! memory"` runs only when docker_routing_config_mode is split/split-unified
//! (elsewhere FRR does not own a config file worth writing).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::l3;
use super::probe::{self, Capability};
use super::store::{self, keys, Platform};
use super::switching::{natural_cmp, WriteError, WriteResult};
use super::CONFIG_DB;

const UNSUPPORTED: &str = "IS-IS requires an image that runs isisd (community SONiC does not \
                           start it in the FRR container)";

// ── running-config parsing ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IsisIfc {
    pub enabled: bool,
    pub circuit_type: Option<String>,
    pub metric: Option<u64>,
    pub passive: bool,
    pub point_to_point: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IsisRunning {
    pub tag: Option<String>,
    pub net: Option<String>,
    /// Contract form: level-1 | level-2 | level-1-2 (FRR's default).
    pub level: String,
    pub dynamic_hostname: bool,
    pub interfaces: BTreeMap<String, IsisIfc>,
}

/// FRR's "level-2-only" ↔ the contract's "level-2".
fn level_from_frr(s: &str) -> String {
    match s {
        "level-2-only" => "level-2".to_string(),
        other => other.to_string(),
    }
}

fn level_to_frr(s: &str) -> &str {
    match s {
        "level-2" => "level-2-only",
        other => other,
    }
}

/// Parse the isis-relevant parts of `show running-config`. Pure.
pub fn parse_running_config(text: &str) -> IsisRunning {
    #[derive(PartialEq)]
    enum Block {
        None,
        Router,
        Interface(String),
    }
    let mut out = IsisRunning {
        level: "level-1-2".to_string(), // FRR default when is-type is absent
        dynamic_hostname: true,         // FRR default; "no hostname dynamic" turns it off
        ..Default::default()
    };
    let mut block = Block::None;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(tag) = line.strip_prefix("router isis ") {
            out.tag = Some(tag.trim().to_string());
            block = Block::Router;
            continue;
        }
        if let Some(name) = line.strip_prefix("interface ") {
            block = Block::Interface(name.trim().to_string());
            continue;
        }
        if line == "exit" || line == "!" || line == "end" {
            block = Block::None;
            continue;
        }
        match &block {
            Block::Router => {
                if let Some(net) = line.strip_prefix("net ") {
                    out.net = Some(net.trim().to_string());
                } else if let Some(level) = line.strip_prefix("is-type ") {
                    out.level = level_from_frr(level.trim());
                } else if line == "no hostname dynamic" {
                    out.dynamic_hostname = false;
                }
            }
            Block::Interface(name) => {
                let ifc = || -> IsisIfc { IsisIfc::default() };
                let entry = out.interfaces.entry(name.clone());
                let ifc = entry.or_insert_with(ifc);
                if line.starts_with("ip router isis ") || line.starts_with("ipv6 router isis ") {
                    ifc.enabled = true;
                } else if let Some(ct) = line.strip_prefix("isis circuit-type ") {
                    ifc.circuit_type = Some(level_from_frr(ct.trim()));
                } else if let Some(mv) = line.strip_prefix("isis metric ") {
                    ifc.metric = mv.trim().parse().ok();
                } else if line == "isis passive" {
                    ifc.passive = true;
                } else if line == "isis network point-to-point" {
                    ifc.point_to_point = true;
                }
            }
            Block::None => {}
        }
    }
    // Interface blocks with no isis statements aren't IS-IS interfaces.
    out.interfaces.retain(|_, ifc| {
        ifc.enabled
            || ifc.circuit_type.is_some()
            || ifc.metric.is_some()
            || ifc.passive
            || ifc.point_to_point
    });
    out
}

#[derive(Debug, Serialize, PartialEq)]
pub struct AdjacencyDoc {
    pub system_id: String,
    pub interface: String,
    pub level: String,
    pub state: String,
    pub holdtime_secs: Option<u64>,
}

/// Parse `show isis neighbor json`
/// ({"areas":[{"circuits":[{"adj": …, "interface": {…}}]}]}). Pure, tolerant.
pub fn parse_neighbors(text: &str) -> Vec<AdjacencyDoc> {
    let mut out = Vec::new();
    let Ok(root) = serde_json::from_str::<serde_json::Value>(text) else {
        return out;
    };
    let Some(areas) = root.get("areas").and_then(|a| a.as_array()) else {
        return out;
    };
    for area in areas {
        let Some(circuits) = area.get("circuits").and_then(|c| c.as_array()) else {
            continue;
        };
        for circuit in circuits {
            let Some(adj) = circuit.get("adj").and_then(|v| v.as_str()) else { continue };
            let ifc = circuit.get("interface").cloned().unwrap_or_default();
            let s = |k: &str| ifc.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let level = match s("circuit-type").as_str() {
                "L1" => "level-1",
                "L2" => "level-2",
                "L1L2" => "level-1-2",
                _ => "unknown",
            };
            // "expires-in": "28s"
            let holdtime = ifc
                .get("expires-in")
                .and_then(|v| v.as_str())
                .and_then(|v| v.trim_end_matches('s').trim().parse().ok());
            out.push(AdjacencyDoc {
                system_id: adj.to_string(),
                interface: s("name"),
                level: level.to_string(),
                state: s("state"),
                holdtime_secs: holdtime,
            });
        }
    }
    out
}

// ── GET /api/routing/isis ───────────────────────────────────────────────────

fn running_config(plat: &mut dyn Platform) -> anyhow::Result<IsisRunning> {
    let out = plat.run("vtysh", &["-c", "show running-config"])?;
    if !out.ok {
        anyhow::bail!("vtysh show running-config failed: {}", out.stderr.trim());
    }
    Ok(parse_running_config(&out.stdout))
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    if !p.isis_supported() {
        return Ok(json!({
            "capability": Capability::no(UNSUPPORTED),
            "instance": null, "interfaces": [], "adjacencies": [],
        }));
    }
    let running = running_config(plat)?;
    let instance = match (&running.tag, &running.net) {
        (Some(_), _) => json!({
            "net": running.net,
            "level": running.level,
            "dynamic_hostname": running.dynamic_hostname,
        }),
        _ => serde_json::Value::Null,
    };

    // Every L3-capable interface appears; IS-IS config merged where present.
    #[derive(Serialize)]
    struct IfcDoc {
        name: String,
        enabled: bool,
        circuit_type: Option<String>,
        metric: Option<u64>,
        passive: bool,
        point_to_point: bool,
    }
    let l3_doc = l3::get_interfaces(plat)?;
    let mut interfaces = Vec::new();
    if let Some(list) = l3_doc["interfaces"].as_array() {
        for l3_if in list {
            let Some(name) = l3_if["name"].as_str() else { continue };
            let ifc = running.interfaces.get(name).cloned().unwrap_or_default();
            interfaces.push(IfcDoc {
                name: name.to_string(),
                enabled: ifc.enabled,
                circuit_type: ifc.circuit_type,
                metric: ifc.metric,
                passive: ifc.passive,
                point_to_point: ifc.point_to_point,
            });
        }
    }
    interfaces.sort_by(|a, b| natural_cmp(&a.name, &b.name));

    let adjacencies = plat
        .run("vtysh", &["-c", "show isis neighbor json"])
        .ok()
        .filter(|o| o.ok)
        .map(|o| parse_neighbors(&o.stdout))
        .unwrap_or_default();

    Ok(json!({
        "capability": Capability::yes(),
        "instance": instance,
        "interfaces": interfaces,
        "adjacencies": adjacencies,
    }))
}

// ── writes (vtysh) ──────────────────────────────────────────────────────────

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

fn require_supported(plat: &mut dyn Platform) -> std::result::Result<probe::Probe, WriteError> {
    let p = probe::current(plat);
    if !p.isis_supported() {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    Ok(p)
}

/// A NET like 49.0001.1921.6800.1001.00: dot-separated hex groups — 2-hex
/// AFI, 4-hex middles, terminating 00 selector.
pub fn valid_net(net: &str) -> bool {
    let parts: Vec<&str> = net.split('.').collect();
    if parts.len() < 4 || parts.len() > 13 {
        return false;
    }
    let hex = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit());
    let (first, rest) = parts.split_first().unwrap();
    let (last, middle) = rest.split_last().unwrap();
    first.len() == 2 && hex(first) && *last == "00" && middle.iter().all(|p| p.len() == 4 && hex(p))
}

/// Run one vtysh configuration batch, then persist per the routing-config
/// mode. The command list is `configure terminal` plus `lines`.
fn vtysh_config(plat: &mut dyn Platform, p: &probe::Probe, lines: &[String]) -> WriteResult {
    let mut args: Vec<&str> = Vec::with_capacity(lines.len() * 2 + 2);
    args.push("-c");
    args.push("configure terminal");
    for line in lines {
        args.push("-c");
        args.push(line);
    }
    let out = plat
        .run("vtysh", &args)
        .map_err(|e| WriteError::Internal(format!("vtysh: {e:#}")))?;
    if !out.ok {
        return Err(WriteError::Internal(format!(
            "vtysh configuration failed: {}",
            if out.stderr.trim().is_empty() { out.stdout.trim() } else { out.stderr.trim() }
        )));
    }
    if p.frr_write_memory_needed() {
        let out = plat
            .run("vtysh", &["-c", "write memory"])
            .map_err(|e| WriteError::Internal(format!("vtysh write memory: {e:#}")))?;
        if !out.ok {
            tracing::warn!("vtysh write memory failed: {}", out.stderr.trim());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Level {
    #[serde(rename = "level-1")]
    Level1,
    #[serde(rename = "level-2")]
    Level2,
    #[serde(rename = "level-1-2")]
    Level12,
}

impl Level {
    fn contract_str(self) -> &'static str {
        match self {
            Level::Level1 => "level-1",
            Level::Level2 => "level-2",
            Level::Level12 => "level-1-2",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct InstanceInput {
    /// null removes the instance.
    pub net: Option<String>,
    pub level: Level,
    #[serde(default = "default_true")]
    pub dynamic_hostname: bool,
}

fn default_true() -> bool {
    true
}

/// The instance tag: whatever is already configured, else "1" (SONiC has no
/// tag conventions of its own; the console never sees the tag).
fn tag_of(running: &IsisRunning) -> String {
    running.tag.clone().unwrap_or_else(|| "1".to_string())
}

pub fn put_instance(plat: &mut dyn Platform, input: &InstanceInput) -> WriteResult {
    let _lock = store::feature_lock("isis");
    let p = require_supported(plat)?;
    let running = running_config(plat).map_err(|e| WriteError::Internal(format!("{e:#}")))?;
    let tag = tag_of(&running);

    let Some(net) = &input.net else {
        // net null removes the instance (idempotently).
        if running.tag.is_none() {
            return Ok(());
        }
        return vtysh_config(plat, &p, &[format!("no router isis {tag}")]);
    };
    if !valid_net(net) {
        return Err(bad(format!(
            "invalid NET {net:?} (expected e.g. 49.0001.1921.6800.1001.00)"
        )));
    }

    let mut lines = vec![format!("router isis {tag}")];
    // A changed NET must be withdrawn first — "net" statements accumulate.
    if let Some(old) = &running.net {
        if old != net {
            lines.push(format!("no net {old}"));
        }
    }
    lines.push(format!("net {net}"));
    lines.push(format!("is-type {}", level_to_frr(input.level.contract_str())));
    lines.push(if input.dynamic_hostname {
        "hostname dynamic".to_string()
    } else {
        "no hostname dynamic".to_string()
    });
    vtysh_config(plat, &p, &lines)
}

#[derive(Debug, Deserialize)]
pub struct InterfaceInput {
    pub enabled: bool,
    pub circuit_type: Option<Level>,
    pub metric: Option<u64>,
    #[serde(default)]
    pub passive: bool,
    #[serde(default)]
    pub point_to_point: bool,
}

pub fn put_interface(plat: &mut dyn Platform, name: &str, input: &InterfaceInput) -> WriteResult {
    let _lock = store::feature_lock("isis");
    let p = require_supported(plat)?;
    if let Some(metric) = input.metric {
        if !(1..=16_777_215).contains(&metric) {
            return Err(bad(format!("invalid metric {metric} (must be 1-16777215)")));
        }
    }
    let exists = match l3::kind_of(name) {
        l3::Kind::Port => plat.exists(CONFIG_DB, &format!("PORT|{name}")),
        l3::Kind::PortChannel => plat.exists(CONFIG_DB, &format!("PORTCHANNEL|{name}")),
        l3::Kind::Vlan => plat.exists(CONFIG_DB, &format!("VLAN|{name}")),
        l3::Kind::Loopback => {
            Ok(!keys(plat, CONFIG_DB, &format!("LOOPBACK_INTERFACE|{name}*")).is_empty())
        }
    }
    .map_err(WriteError::Redis)?;
    if !exists {
        return Err(WriteError::NotFound(format!("no such interface {name}")));
    }
    let running = running_config(plat).map_err(|e| WriteError::Internal(format!("{e:#}")))?;
    if running.tag.is_none() {
        return Err(bad(
            "no IS-IS instance (set a NET via PUT /api/routing/isis/instance first)".to_string(),
        ));
    }
    let tag = tag_of(&running);

    let mut lines = vec![format!("interface {name}")];
    if input.enabled {
        lines.push(format!("ip router isis {tag}"));
        // The body is the full desired state for the interface.
        match input.circuit_type {
            Some(level) => lines.push(format!(
                "isis circuit-type {}",
                level_to_frr(level.contract_str())
            )),
            None => lines.push("no isis circuit-type".to_string()),
        }
        match input.metric {
            Some(metric) => lines.push(format!("isis metric {metric}")),
            None => lines.push("no isis metric".to_string()),
        }
        lines.push(if input.passive {
            "isis passive".to_string()
        } else {
            "no isis passive".to_string()
        });
        lines.push(if input.point_to_point {
            "isis network point-to-point".to_string()
        } else {
            "no isis network point-to-point".to_string()
        });
    } else {
        lines.push(format!("no ip router isis {tag}"));
    }
    vtysh_config(plat, &p, &lines)
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::super::store::CmdOutput;
    use super::*;

    const RUNNING: &str = "\
frr version 8.5\n!\nrouter isis CORE\n net 49.0001.1921.6800.1001.00\n is-type level-2-only\n \
no hostname dynamic\nexit\n!\ninterface Ethernet0\n ip router isis CORE\n isis metric 50\n \
isis network point-to-point\nexit\n!\ninterface Ethernet4\n description not-isis\nexit\n!\n";

    fn isis_capable() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file(
            "/etc/sonic/sonic_version.yml",
            "build_version: '4.1.1'\nrelease: 'Enterprise SONiC'\n",
        );
        m.seed(CONFIG_DB, "PORT|Ethernet0", &[("admin_status", "up")]);
        m.on_cmd(
            &["vtysh", "-c", "show daemons"],
            CmdOutput { ok: true, stdout: "zebra bgpd isisd staticd".into(), stderr: String::new() },
        );
        m.on_cmd(
            &["vtysh", "-c", "show running-config"],
            CmdOutput { ok: true, stdout: RUNNING.into(), stderr: String::new() },
        );
        m
    }

    #[test]
    fn parses_running_config() {
        let r = parse_running_config(RUNNING);
        assert_eq!(r.tag.as_deref(), Some("CORE"));
        assert_eq!(r.net.as_deref(), Some("49.0001.1921.6800.1001.00"));
        assert_eq!(r.level, "level-2");
        assert!(!r.dynamic_hostname);
        let e0 = r.interfaces.get("Ethernet0").unwrap();
        assert!(e0.enabled);
        assert_eq!(e0.metric, Some(50));
        assert!(e0.point_to_point);
        assert!(!e0.passive);
        // Interface blocks with no isis statements are dropped.
        assert!(!r.interfaces.contains_key("Ethernet4"));
        // Empty config → defaults.
        let empty = parse_running_config("frr version 8.5\n!\n");
        assert_eq!(empty.tag, None);
        assert_eq!(empty.level, "level-1-2");
        assert!(empty.dynamic_hostname);
    }

    #[test]
    fn parses_neighbors_json() {
        let text = r#"{"areas":[{"area":"CORE","circuits":[
            {"circuit":0,"adj":"spine1","interface":{"name":"Ethernet0","state":"Up","circuit-type":"L2","expires-in":"28s"}},
            {"circuit":0,"adj":"spine2","interface":{"name":"Ethernet4","state":"Init","circuit-type":"L1L2"}}
        ]}]}"#;
        let adjs = parse_neighbors(text);
        assert_eq!(adjs.len(), 2);
        assert_eq!(adjs[0].system_id, "spine1");
        assert_eq!(adjs[0].interface, "Ethernet0");
        assert_eq!(adjs[0].level, "level-2");
        assert_eq!(adjs[0].state, "Up");
        assert_eq!(adjs[0].holdtime_secs, Some(28));
        assert_eq!(adjs[1].level, "level-1-2");
        assert_eq!(adjs[1].holdtime_secs, None);
        assert!(parse_neighbors("garbage").is_empty());
    }

    #[test]
    fn community_is_unsupported() {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202505.1'\n");
        m.on_cmd(
            &["vtysh", "-c", "show daemons"],
            CmdOutput { ok: true, stdout: "zebra bgpd staticd".into(), stderr: String::new() },
        );
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        assert_eq!(doc["instance"], serde_json::Value::Null);
        let err = put_instance(
            &mut m,
            &InstanceInput {
                net: Some("49.0001.1921.6800.1001.00".into()),
                level: Level::Level2,
                dynamic_hostname: true,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
        // No configuration command ever ran.
        assert!(!m.log.iter().any(|l| l.contains("configure terminal")), "{:?}", m.log);
    }

    #[test]
    fn get_merges_running_config_over_l3_interfaces() {
        let mut m = isis_capable();
        m.seed(CONFIG_DB, "PORT|Ethernet4", &[("admin_status", "up")]);
        m.on_cmd(
            &["vtysh", "-c", "show isis neighbor json"],
            CmdOutput {
                ok: true,
                stdout: r#"{"areas":[{"circuits":[{"adj":"spine1","interface":{"name":"Ethernet0","state":"Up","circuit-type":"L2","expires-in":"30s"}}]}]}"#.into(),
                stderr: String::new(),
            },
        );
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["instance"]["net"], "49.0001.1921.6800.1001.00");
        assert_eq!(doc["instance"]["level"], "level-2");
        assert_eq!(doc["instance"]["dynamic_hostname"], false);
        let ifs = doc["interfaces"].as_array().unwrap();
        let e0 = ifs.iter().find(|i| i["name"] == "Ethernet0").unwrap();
        assert_eq!(e0["enabled"], true);
        assert_eq!(e0["metric"], 50);
        assert_eq!(e0["point_to_point"], true);
        let e4 = ifs.iter().find(|i| i["name"] == "Ethernet4").unwrap();
        assert_eq!(e4["enabled"], false);
        assert_eq!(doc["adjacencies"][0]["system_id"], "spine1");
    }

    #[test]
    fn instance_put_replaces_net_and_persists_in_split_mode() {
        let mut m = isis_capable();
        m.seed(
            CONFIG_DB,
            "DEVICE_METADATA|localhost",
            &[("docker_routing_config_mode", "split")],
        );
        put_instance(
            &mut m,
            &InstanceInput {
                net: Some("49.0002.aaaa.bbbb.cccc.00".into()),
                level: Level::Level12,
                dynamic_hostname: true,
            },
        )
        .unwrap();
        let cfg = m
            .log
            .iter()
            .find(|l| l.contains("configure terminal"))
            .expect("no vtysh config run");
        assert!(cfg.contains("router isis CORE"), "{cfg}");
        assert!(cfg.contains("no net 49.0001.1921.6800.1001.00"), "{cfg}");
        assert!(cfg.contains("net 49.0002.aaaa.bbbb.cccc.00"), "{cfg}");
        assert!(cfg.contains("is-type level-1-2"), "{cfg}");
        assert!(cfg.contains("hostname dynamic"), "{cfg}");
        // split mode → write memory ran.
        assert!(m.log.iter().any(|l| l.contains("write memory")), "{:?}", m.log);
        // Bad NET → 400 before any vtysh config.
        let err = put_instance(
            &mut m,
            &InstanceInput { net: Some("nope".into()), level: Level::Level1, dynamic_hostname: true },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
    }

    #[test]
    fn instance_removal_and_interface_full_state() {
        let mut m = isis_capable();
        put_instance(
            &mut m,
            &InstanceInput { net: None, level: Level::Level12, dynamic_hostname: true },
        )
        .unwrap();
        assert!(
            m.log.iter().any(|l| l.contains("no router isis CORE")),
            "{:?}",
            m.log
        );
        // In separated mode no write memory runs.
        assert!(!m.log.iter().any(|l| l.contains("write memory")), "{:?}", m.log);

        m.log.clear();
        put_interface(
            &mut m,
            "Ethernet0",
            &InterfaceInput {
                enabled: true,
                circuit_type: Some(Level::Level2),
                metric: None,
                passive: true,
                point_to_point: false,
            },
        )
        .unwrap();
        let cfg = m.log.iter().find(|l| l.contains("configure terminal")).unwrap();
        assert!(cfg.contains("interface Ethernet0"), "{cfg}");
        assert!(cfg.contains("ip router isis CORE"), "{cfg}");
        assert!(cfg.contains("isis circuit-type level-2-only"), "{cfg}");
        assert!(cfg.contains("no isis metric"), "{cfg}");
        assert!(cfg.contains("isis passive"), "{cfg}");
        assert!(cfg.contains("no isis network point-to-point"), "{cfg}");

        m.log.clear();
        put_interface(
            &mut m,
            "Ethernet0",
            &InterfaceInput {
                enabled: false,
                circuit_type: None,
                metric: None,
                passive: false,
                point_to_point: false,
            },
        )
        .unwrap();
        let cfg = m.log.iter().find(|l| l.contains("configure terminal")).unwrap();
        assert!(cfg.contains("no ip router isis CORE"), "{cfg}");
        // Unknown interface → 404.
        let err = put_interface(
            &mut m,
            "Ethernet99",
            &InterfaceInput {
                enabled: true,
                circuit_type: None,
                metric: None,
                passive: false,
                point_to_point: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
    }

    #[test]
    fn net_validation() {
        assert!(valid_net("49.0001.1921.6800.1001.00"));
        assert!(valid_net("49.0001.0000.0000.0001.00"));
        assert!(!valid_net("49.0001.1921.6800.1001.01")); // selector must be 00
        assert!(!valid_net("49.00.01")); // too few groups
        assert!(!valid_net("xx.0001.0000.0000.0001.00"));
        assert!(!valid_net(""));
    }
}
