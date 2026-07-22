//! Spanning tree and loop protection for the console's Configure → Switching
//! → Spanning Tree / Loop Protection pages.
//!
//! Config lives in CONFIG_DB: `STP|GLOBAL` (mode pvst|mst, timers, priority),
//! `STP_VLAN|Vlan<id>`, `STP_PORT|<ifname>` (the merged community code uses
//! STP_PORT/STP_VLAN_PORT — the older HLD names STP_INTF/STP_VLAN_INTF are
//! wrong), `STP_MST|GLOBAL`, `STP_MST_INST|MST_INSTANCE:INSTANCE<id>`.
//! Booleans are "true"/"false" strings.
//!
//! Operational state comes from APPL_DB: `STP_VLAN_TABLE:Vlan<id>`
//! (bridge_id, root_bridge_id, root_port, root_path_cost,
//! topology_change_count, last_topology_change),
//! `STP_VLAN_PORT_TABLE:Vlan<id>:<ifname>` (port_state, bpdu counters,
//! root_guard_timer) and `STP_PORT_TABLE:<ifname>` (bpdu_guard_shutdown
//! yes/no). A port's summary `state` is the worst state across its VLAN
//! instances; is_root = bridge_id == root_bridge_id.
//!
//! Writes replicate what `config spanning_tree …` does: VLAN existence and
//! the STATE_DB `STP_TABLE|GLOBAL` max_stp_inst limit are validated, enabling
//! STP seeds STP_VLAN/STP_PORT rows for the existing L2 topology, and
//! disabling removes every STP table.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, field, key_suffix, keys, row, two_parts, Platform};
use super::switching::{natural_cmp, parse_bool, parse_num, present, WriteError, WriteResult};
use super::{APPL_DB, CONFIG_DB, STATE_DB};

// PVST defaults (also what `config spanning_tree enable` writes).
const DEF_FORWARD_DELAY: u32 = 15;
const DEF_HELLO: u32 = 2;
const DEF_MAX_AGE: u32 = 20;
const DEF_PRIORITY: u32 = 32768;
const DEF_ROOTGUARD: u32 = 30;
const DEF_MAX_STP_INST: u64 = 255;

fn unsupported_reason() -> String {
    "spanning tree requires an STP-capable image (community docker-stp, a 202505+ build with \
     INCLUDE_STP, or Enterprise SONiC)"
        .to_string()
}

fn capability(p: &probe::Probe) -> Capability {
    if p.stp_supported() {
        Capability::yes()
    } else {
        Capability::no(unsupported_reason())
    }
}

// ── GET /api/switching/spanning-tree ────────────────────────────────────────

#[derive(Debug, Serialize)]
struct VlanDoc {
    vlan_id: u32,
    enabled: bool,
    priority: Option<u32>,
    forward_delay: Option<u32>,
    hello_time: Option<u32>,
    max_age: Option<u32>,
    bridge_id: Option<String>,
    root_bridge_id: Option<String>,
    is_root: Option<bool>,
    root_port: Option<String>,
    root_path_cost: Option<u64>,
    topology_change_count: Option<u64>,
    last_topology_change_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct PortDoc {
    name: String,
    enabled: bool,
    priority: Option<u32>,
    path_cost: Option<u64>,
    portfast: bool,
    uplink_fast: bool,
    edge_port: Option<bool>,
    link_type: Option<String>,
    bpdu_guard: bool,
    bpdu_guard_do_disable: bool,
    root_guard: bool,
    state: Option<String>,
    bpdu_guard_shutdown: Option<bool>,
    bpdu_sent: Option<u64>,
    bpdu_received: Option<u64>,
}

/// Per-port digest of the APPL_DB STP_VLAN_PORT_TABLE rows.
#[derive(Debug, Default, Clone)]
pub struct PortOper {
    pub worst_state: Option<String>,
    pub bpdu_sent: Option<u64>,
    pub bpdu_received: Option<u64>,
    pub root_guard_active: bool,
}

/// Rank a port state by badness; unknown strings rank worst so a port in a
/// state we can't classify is never summarized as healthy.
pub fn state_severity(state: &str) -> u8 {
    match state.to_ascii_lowercase().as_str() {
        "forwarding" => 0,
        "learning" => 1,
        "listening" => 2,
        "blocking" => 3,
        "disabled" => 4,
        _ => 5,
    }
}

/// Fold one STP_VLAN_PORT_TABLE row into a port's digest. Pure.
pub fn fold_port_oper(digest: &mut PortOper, row: &HashMap<String, String>) {
    if let Some(state) = field(row, "port_state") {
        let state = state.to_ascii_lowercase();
        let worse = digest
            .worst_state
            .as_deref()
            .map(|cur| state_severity(&state) > state_severity(cur))
            .unwrap_or(true);
        if worse {
            digest.worst_state = Some(state);
        }
    }
    if let Some(n) = parse_num(field(row, "bpdu_sent")) {
        *digest.bpdu_sent.get_or_insert(0) += n;
    }
    if let Some(n) = parse_num(field(row, "bpdu_received")) {
        *digest.bpdu_received.get_or_insert(0) += n;
    }
    if field(row, "root_guard_timer").map(|v| v != "0").unwrap_or(false) {
        digest.root_guard_active = true;
    }
}

fn num32(h: &HashMap<String, String>, k: &str) -> Option<u32> {
    parse_num(field(h, k)).and_then(|n| u32::try_from(n).ok())
}

/// The L2 interface set STP can run on: every VLAN member (ports and
/// PortChannels) plus anything that already has an STP_PORT row.
fn l2_interfaces(plat: &mut dyn Platform) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for key in keys(plat, CONFIG_DB, "VLAN_MEMBER|*") {
        if let Some((_, member)) = two_parts(&key, "VLAN_MEMBER|") {
            names.push(member.to_string());
        }
    }
    for key in keys(plat, CONFIG_DB, "STP_PORT|*") {
        if let Some(name) = key_suffix(&key, "STP_PORT|") {
            names.push(name.to_string());
        }
    }
    names.sort_by(|a, b| natural_cmp(a, b));
    names.dedup();
    names
}

/// Per-port digests from one pass over APPL_DB STP_VLAN_PORT_TABLE.
fn port_oper_digests(plat: &mut dyn Platform) -> HashMap<String, PortOper> {
    let mut out: HashMap<String, PortOper> = HashMap::new();
    for key in keys(plat, APPL_DB, "STP_VLAN_PORT_TABLE:*") {
        let Some(rest) = key.strip_prefix("STP_VLAN_PORT_TABLE:") else { continue };
        let Some((_vlan, port)) = rest.split_once(':') else { continue };
        if port.is_empty() {
            continue;
        }
        let r = row(plat, APPL_DB, &key);
        fold_port_oper(out.entry(port.to_string()).or_default(), &r);
    }
    out
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    let cap = capability(&p);
    if !cap.supported {
        return Ok(json!({
            "capability": cap, "modes_supported": [],
            "global": null, "vlans": [], "ports": [],
        }));
    }

    let global_row = plat.hgetall(CONFIG_DB, "STP|GLOBAL")?;
    let enabled_globally = !global_row.is_empty();
    let global = if enabled_globally {
        let mode = field(&global_row, "mode").unwrap_or("pvst").to_string();
        let mst = row(plat, CONFIG_DB, "STP_MST|GLOBAL");
        json!({
            "mode": mode,
            "rootguard_timeout": num32(&global_row, "rootguard_timeout").unwrap_or(DEF_ROOTGUARD),
            "forward_delay": num32(&global_row, "forward_delay").unwrap_or(DEF_FORWARD_DELAY),
            "hello_time": num32(&global_row, "hello_time").unwrap_or(DEF_HELLO),
            "max_age": num32(&global_row, "max_age").unwrap_or(DEF_MAX_AGE),
            "priority": num32(&global_row, "priority").unwrap_or(DEF_PRIORITY),
            "region_name": field(&mst, "name"),
            "revision": num32(&mst, "revision"),
            "max_hops": num32(&mst, "max_hops"),
        })
    } else {
        serde_json::Value::Null
    };

    // Every CONFIG_DB VLAN appears; STP_VLAN rows override the default
    // (`config spanning_tree enable` runs STP on all VLANs).
    let mut vlan_ids: Vec<u32> = keys(plat, CONFIG_DB, "VLAN|*")
        .iter()
        .filter_map(|k| key_suffix(k, "VLAN|"))
        .filter_map(super::switching::vlan_id_from_name)
        .collect();
    for key in keys(plat, CONFIG_DB, "STP_VLAN|*") {
        if let Some(name) = key_suffix(&key, "STP_VLAN|") {
            if let Some(id) = super::switching::vlan_id_from_name(name) {
                vlan_ids.push(id);
            }
        }
    }
    vlan_ids.sort_unstable();
    vlan_ids.dedup();
    let mut vlans = Vec::with_capacity(vlan_ids.len());
    for id in vlan_ids {
        let cfg = row(plat, CONFIG_DB, &format!("STP_VLAN|Vlan{id}"));
        let oper = row(plat, APPL_DB, &format!("STP_VLAN_TABLE:Vlan{id}"));
        let bridge_id = field(&oper, "bridge_id").map(str::to_string);
        let root_bridge_id = field(&oper, "root_bridge_id").map(str::to_string);
        let is_root = match (&bridge_id, &root_bridge_id) {
            (Some(b), Some(r)) => Some(b == r),
            _ => None,
        };
        vlans.push(VlanDoc {
            vlan_id: id,
            enabled: parse_bool(field(&cfg, "enabled")).unwrap_or(enabled_globally),
            priority: num32(&cfg, "priority"),
            forward_delay: num32(&cfg, "forward_delay"),
            hello_time: num32(&cfg, "hello_time"),
            max_age: num32(&cfg, "max_age"),
            bridge_id,
            root_bridge_id,
            is_root,
            root_port: field(&oper, "root_port").map(str::to_string),
            root_path_cost: parse_num(field(&oper, "root_path_cost")),
            topology_change_count: parse_num(field(&oper, "topology_change_count")),
            last_topology_change_secs: parse_num(field(&oper, "last_topology_change")),
        });
    }

    let digests = port_oper_digests(plat);
    let mut ports = Vec::new();
    for name in l2_interfaces(plat) {
        let cfg = row(plat, CONFIG_DB, &format!("STP_PORT|{name}"));
        let appl = row(plat, APPL_DB, &format!("STP_PORT_TABLE:{name}"));
        let digest = digests.get(&name).cloned().unwrap_or_default();
        ports.push(PortDoc {
            enabled: parse_bool(field(&cfg, "enabled")).unwrap_or(enabled_globally),
            priority: num32(&cfg, "priority"),
            path_cost: parse_num(field(&cfg, "path_cost")),
            portfast: parse_bool(field(&cfg, "portfast")).unwrap_or(false),
            uplink_fast: parse_bool(field(&cfg, "uplink_fast")).unwrap_or(false),
            edge_port: parse_bool(field(&cfg, "edge_port")),
            link_type: field(&cfg, "link_type").map(str::to_string),
            bpdu_guard: parse_bool(field(&cfg, "bpdu_guard")).unwrap_or(false),
            bpdu_guard_do_disable: parse_bool(field(&cfg, "bpdu_guard_do_disable"))
                .unwrap_or(false),
            root_guard: parse_bool(field(&cfg, "root_guard")).unwrap_or(false),
            state: digest.worst_state.clone(),
            bpdu_guard_shutdown: guard_shutdown(&appl),
            bpdu_sent: digest.bpdu_sent,
            bpdu_received: digest.bpdu_received,
            name,
        });
    }

    Ok(json!({
        "capability": cap,
        "modes_supported": p.stp_modes(),
        "global": global,
        "vlans": vlans,
        "ports": ports,
    }))
}

/// APPL_DB STP_PORT_TABLE bpdu_guard_shutdown is "yes"/"no"; anything else
/// (or no row) is unknown.
pub fn guard_shutdown(appl: &HashMap<String, String>) -> Option<bool> {
    match field(appl, "bpdu_guard_shutdown")? {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

// ── PUT /api/switching/spanning-tree/global ─────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Pvst,
    Mst,
    Disabled,
}

#[derive(Debug, Deserialize)]
pub struct GlobalInput {
    pub mode: Mode,
    pub rootguard_timeout: Option<u32>,
    pub forward_delay: Option<u32>,
    pub hello_time: Option<u32>,
    pub max_age: Option<u32>,
    pub priority: Option<u32>,
    pub region_name: Option<String>,
    pub revision: Option<u32>,
    pub max_hops: Option<u32>,
}

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

fn range(name: &str, v: u32, lo: u32, hi: u32) -> std::result::Result<(), String> {
    if (lo..=hi).contains(&v) {
        Ok(())
    } else {
        Err(format!("invalid {name} {v} (must be {lo}-{hi})"))
    }
}

/// The IEEE relation `config spanning_tree` enforces on the effective values:
/// 2*(forward_delay-1) >= max_age >= 2*(hello_time+1).
pub fn check_timer_relation(
    forward_delay: u32,
    hello_time: u32,
    max_age: u32,
) -> std::result::Result<(), String> {
    range("forward_delay", forward_delay, 4, 30)?;
    range("hello_time", hello_time, 1, 10)?;
    range("max_age", max_age, 6, 40)?;
    if 2 * (forward_delay - 1) < max_age || max_age < 2 * (hello_time + 1) {
        return Err(format!(
            "timers must satisfy 2*(forward_delay-1) >= max_age >= 2*(hello_time+1) \
             (got forward_delay {forward_delay}, max_age {max_age}, hello_time {hello_time})"
        ));
    }
    Ok(())
}

pub fn check_bridge_priority(v: u32) -> std::result::Result<(), String> {
    if v > 61440 || v % 4096 != 0 {
        Err(format!("invalid priority {v} (must be 0-61440 in steps of 4096)"))
    } else {
        Ok(())
    }
}

fn max_stp_instances(plat: &mut dyn Platform) -> u64 {
    parse_num(field(&row(plat, STATE_DB, "STP_TABLE|GLOBAL"), "max_stp_inst"))
        .unwrap_or(DEF_MAX_STP_INST)
}

fn require_supported(plat: &mut dyn Platform) -> std::result::Result<probe::Probe, WriteError> {
    let p = probe::current(plat);
    if !p.stp_supported() {
        return Err(WriteError::Conflict(unsupported_reason()));
    }
    Ok(p)
}

pub fn put_global(plat: &mut dyn Platform, input: &GlobalInput) -> WriteResult {
    let _lock = store::feature_lock("stp");
    let p = require_supported(plat)?;

    if input.mode == Mode::Disabled {
        return disable(plat);
    }
    if input.mode == Mode::Mst && !p.stp_modes().contains(&"mst") {
        return Err(WriteError::Unprocessable(
            "MST is not supported on this image (PVST only)".to_string(),
        ));
    }

    let current = plat.hgetall(CONFIG_DB, "STP|GLOBAL").map_err(WriteError::Redis)?;
    let enabling = current.is_empty();
    // Effective values: payload → current row → PVST defaults; the relation
    // is checked on what will actually be in effect.
    let fd = input
        .forward_delay
        .or_else(|| num32(&current, "forward_delay"))
        .unwrap_or(DEF_FORWARD_DELAY);
    let hello = input.hello_time.or_else(|| num32(&current, "hello_time")).unwrap_or(DEF_HELLO);
    let max_age = input.max_age.or_else(|| num32(&current, "max_age")).unwrap_or(DEF_MAX_AGE);
    let priority = input.priority.or_else(|| num32(&current, "priority")).unwrap_or(DEF_PRIORITY);
    let rootguard = input
        .rootguard_timeout
        .or_else(|| num32(&current, "rootguard_timeout"))
        .unwrap_or(DEF_ROOTGUARD);
    check_timer_relation(fd, hello, max_age).map_err(bad)?;
    check_bridge_priority(priority).map_err(bad)?;
    range("rootguard_timeout", rootguard, 5, 600).map_err(bad)?;
    if let Some(hops) = input.max_hops {
        range("max_hops", hops, 1, 40).map_err(bad)?;
    }

    let vlan_keys = plat.scan(CONFIG_DB, "VLAN|*").map_err(WriteError::Redis)?;
    if enabling {
        // `config spanning_tree enable` refuses to start more instances than
        // stpd advertises it can run.
        let limit = max_stp_instances(plat);
        if vlan_keys.len() as u64 > limit {
            return Err(WriteError::Unprocessable(format!(
                "enabling spanning tree needs {} STP instances but the platform supports {limit} \
                 (STATE_DB STP_TABLE|GLOBAL max_stp_inst)",
                vlan_keys.len()
            )));
        }
    }
    let l2 = l2_interfaces(plat);

    let mode = if input.mode == Mode::Mst { "mst" } else { "pvst" };
    store::apply(plat, |b| {
        let (fd_s, hello_s, age_s, prio_s, rg_s) = (
            fd.to_string(),
            hello.to_string(),
            max_age.to_string(),
            priority.to_string(),
            rootguard.to_string(),
        );
        b.hset(
            CONFIG_DB,
            "STP|GLOBAL",
            &[
                ("mode", mode),
                ("forward_delay", &fd_s),
                ("hello_time", &hello_s),
                ("max_age", &age_s),
                ("priority", &prio_s),
                ("rootguard_timeout", &rg_s),
            ],
        )?;
        if mode == "mst" {
            let mut fields: Vec<(&str, String)> = Vec::new();
            if let Some(name) = &input.region_name {
                fields.push(("name", name.clone()));
            }
            if let Some(rev) = input.revision {
                fields.push(("revision", rev.to_string()));
            }
            if let Some(hops) = input.max_hops {
                fields.push(("max_hops", hops.to_string()));
            }
            let refs: Vec<(&str, &str)> =
                fields.iter().map(|(f, v)| (*f, v.as_str())).collect();
            if refs.is_empty() {
                b.hset(CONFIG_DB, "STP_MST|GLOBAL", &[("NULL", "NULL")])?;
            } else {
                b.hset(CONFIG_DB, "STP_MST|GLOBAL", &refs)?;
            }
        }
        if enabling {
            // Seed the per-VLAN and per-port rows the CLI would create.
            for key in &vlan_keys {
                if let Some(name) = key_suffix(key, "VLAN|") {
                    b.hset(CONFIG_DB, &format!("STP_VLAN|{name}"), &[("enabled", "true")])?;
                }
            }
            for port in &l2 {
                b.hset(CONFIG_DB, &format!("STP_PORT|{port}"), &[("enabled", "true")])?;
            }
        }
        Ok(())
    })
    .map_err(WriteError::Redis)
}

/// `config spanning_tree disable`: STP|GLOBAL and every dependent table go.
fn disable(plat: &mut dyn Platform) -> WriteResult {
    let mut all = Vec::new();
    for pattern in [
        "STP|GLOBAL",
        "STP_VLAN|*",
        "STP_PORT|*",
        "STP_VLAN_PORT|*",
        "STP_MST|*",
        "STP_MST_INST|*",
        "STP_MST_PORT|*",
    ] {
        all.extend(plat.scan(CONFIG_DB, pattern).map_err(WriteError::Redis)?);
    }
    for key in all {
        plat.del(CONFIG_DB, &key).map_err(WriteError::Redis)?;
    }
    Ok(())
}

// ── PUT /api/switching/spanning-tree/vlans/{vlan_id} ────────────────────────

#[derive(Debug, Deserialize)]
pub struct VlanInput {
    pub enabled: bool,
    #[serde(default, deserialize_with = "present")]
    pub priority: Option<Option<u32>>,
    #[serde(default, deserialize_with = "present")]
    pub forward_delay: Option<Option<u32>>,
    #[serde(default, deserialize_with = "present")]
    pub hello_time: Option<Option<u32>>,
    #[serde(default, deserialize_with = "present")]
    pub max_age: Option<Option<u32>>,
}

pub fn put_vlan(plat: &mut dyn Platform, vlan_id: u32, input: &VlanInput) -> WriteResult {
    let _lock = store::feature_lock("stp");
    require_supported(plat)?;
    if let Some(Some(v)) = input.priority {
        check_bridge_priority(v).map_err(bad)?;
    }
    if let Some(Some(v)) = input.forward_delay {
        range("forward_delay", v, 4, 30).map_err(bad)?;
    }
    if let Some(Some(v)) = input.hello_time {
        range("hello_time", v, 1, 10).map_err(bad)?;
    }
    if let Some(Some(v)) = input.max_age {
        range("max_age", v, 6, 40).map_err(bad)?;
    }

    let key = format!("STP_VLAN|Vlan{vlan_id}");
    if !plat.exists(CONFIG_DB, &format!("VLAN|Vlan{vlan_id}")).map_err(WriteError::Redis)? {
        return Err(WriteError::NotFound(format!("no such VLAN Vlan{vlan_id}")));
    }
    if !plat.exists(CONFIG_DB, "STP|GLOBAL").map_err(WriteError::Redis)? {
        return Err(WriteError::Conflict("spanning tree is disabled globally".to_string()));
    }
    if input.enabled {
        // Enabling one more instance must stay within the platform limit.
        let mut on = 0u64;
        for k in plat.scan(CONFIG_DB, "STP_VLAN|*").map_err(WriteError::Redis)? {
            if k == key {
                continue;
            }
            let r = row(plat, CONFIG_DB, &k);
            if parse_bool(field(&r, "enabled")).unwrap_or(true) {
                on += 1;
            }
        }
        let limit = max_stp_instances(plat);
        if on + 1 > limit {
            return Err(WriteError::Unprocessable(format!(
                "cannot enable STP on Vlan{vlan_id}: the platform supports {limit} STP instances"
            )));
        }
    }

    plat.hset(CONFIG_DB, &key, &[("enabled", if input.enabled { "true" } else { "false" })])
        .map_err(WriteError::Redis)?;
    for (name, v) in [
        ("priority", &input.priority),
        ("forward_delay", &input.forward_delay),
        ("hello_time", &input.hello_time),
        ("max_age", &input.max_age),
    ] {
        match v {
            Some(Some(n)) => plat
                .hset(CONFIG_DB, &key, &[(name, &n.to_string())])
                .map_err(WriteError::Redis)?,
            // null override = inherit the global value again.
            Some(None) => plat.hdel(CONFIG_DB, &key, &[name]).map_err(WriteError::Redis)?,
            None => {}
        }
    }
    Ok(())
}

// ── PUT /api/switching/spanning-tree/ports/{name} ───────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum LinkType {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "point-to-point")]
    PointToPoint,
    #[serde(rename = "shared")]
    Shared,
}

#[derive(Debug, Deserialize)]
pub struct PortInput {
    pub enabled: bool,
    #[serde(default, deserialize_with = "present")]
    pub priority: Option<Option<u32>>,
    #[serde(default, deserialize_with = "present")]
    pub path_cost: Option<Option<u64>>,
    pub portfast: Option<bool>,
    pub uplink_fast: Option<bool>,
    pub edge_port: Option<bool>,
    pub link_type: Option<LinkType>,
    pub bpdu_guard: Option<bool>,
    pub bpdu_guard_do_disable: Option<bool>,
    pub root_guard: Option<bool>,
}

pub fn check_port_priority(v: u32) -> std::result::Result<(), String> {
    if v > 240 || v % 16 != 0 {
        Err(format!("invalid port priority {v} (must be 0-240 in steps of 16)"))
    } else {
        Ok(())
    }
}

pub fn check_path_cost(v: u64) -> std::result::Result<(), String> {
    if (1..=200_000_000).contains(&v) {
        Ok(())
    } else {
        Err(format!("invalid path_cost {v} (must be 1-200000000)"))
    }
}

fn interface_exists(plat: &mut dyn Platform, name: &str) -> std::result::Result<bool, WriteError> {
    Ok(plat.exists(CONFIG_DB, &format!("PORT|{name}")).map_err(WriteError::Redis)?
        || plat.exists(CONFIG_DB, &format!("PORTCHANNEL|{name}")).map_err(WriteError::Redis)?)
}

pub fn put_port(plat: &mut dyn Platform, name: &str, input: &PortInput) -> WriteResult {
    let _lock = store::feature_lock("stp");
    require_supported(plat)?;
    if let Some(Some(v)) = input.priority {
        check_port_priority(v).map_err(bad)?;
    }
    if let Some(Some(v)) = input.path_cost {
        check_path_cost(v).map_err(bad)?;
    }
    if !interface_exists(plat, name)? {
        return Err(WriteError::NotFound(format!("no such interface {name}")));
    }
    if !plat.exists(CONFIG_DB, "STP|GLOBAL").map_err(WriteError::Redis)? {
        return Err(WriteError::Conflict("spanning tree is disabled globally".to_string()));
    }

    let key = format!("STP_PORT|{name}");
    let as_bool = |v: bool| if v { "true" } else { "false" };
    plat.hset(CONFIG_DB, &key, &[("enabled", as_bool(input.enabled))])
        .map_err(WriteError::Redis)?;
    match input.priority {
        Some(Some(v)) => plat
            .hset(CONFIG_DB, &key, &[("priority", &v.to_string())])
            .map_err(WriteError::Redis)?,
        Some(None) => plat.hdel(CONFIG_DB, &key, &["priority"]).map_err(WriteError::Redis)?,
        None => {}
    }
    match input.path_cost {
        Some(Some(v)) => plat
            .hset(CONFIG_DB, &key, &[("path_cost", &v.to_string())])
            .map_err(WriteError::Redis)?,
        Some(None) => plat.hdel(CONFIG_DB, &key, &["path_cost"]).map_err(WriteError::Redis)?,
        None => {}
    }
    for (fname, v) in [
        ("portfast", input.portfast),
        ("uplink_fast", input.uplink_fast),
        ("edge_port", input.edge_port),
        ("bpdu_guard", input.bpdu_guard),
        ("bpdu_guard_do_disable", input.bpdu_guard_do_disable),
        ("root_guard", input.root_guard),
    ] {
        if let Some(v) = v {
            plat.hset(CONFIG_DB, &key, &[(fname, as_bool(v))]).map_err(WriteError::Redis)?;
        }
    }
    match input.link_type {
        // auto = no explicit override in CONFIG_DB.
        Some(LinkType::Auto) => {
            plat.hdel(CONFIG_DB, &key, &["link_type"]).map_err(WriteError::Redis)?
        }
        Some(LinkType::PointToPoint) => plat
            .hset(CONFIG_DB, &key, &[("link_type", "point-to-point")])
            .map_err(WriteError::Redis)?,
        Some(LinkType::Shared) => {
            plat.hset(CONFIG_DB, &key, &[("link_type", "shared")]).map_err(WriteError::Redis)?
        }
        None => {}
    }
    Ok(())
}

// ── loop protection ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct LoopPortDoc {
    name: String,
    stp_enabled: bool,
    bpdu_guard: bool,
    bpdu_guard_do_disable: bool,
    root_guard: bool,
    bpdu_guard_shutdown: Option<bool>,
    root_guard_active: Option<bool>,
}

/// GET /api/switching/loop-protection — BPDU/root guard is STP's, so the
/// capability condition is spanning tree's.
pub fn get_loop_protection(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    let cap = capability(&p);
    if !cap.supported {
        return Ok(json!({ "capability": cap, "ports": [] }));
    }
    let enabled_globally = plat.exists(CONFIG_DB, "STP|GLOBAL")?;
    let digests = port_oper_digests(plat);
    let mut ports = Vec::new();
    for name in l2_interfaces(plat) {
        let cfg = row(plat, CONFIG_DB, &format!("STP_PORT|{name}"));
        let appl = row(plat, APPL_DB, &format!("STP_PORT_TABLE:{name}"));
        // root_guard_active is only knowable when APPL_DB published per-VLAN
        // rows for the port at all.
        let root_guard_active = digests.get(&name).map(|d| d.root_guard_active);
        ports.push(LoopPortDoc {
            stp_enabled: parse_bool(field(&cfg, "enabled")).unwrap_or(enabled_globally),
            bpdu_guard: parse_bool(field(&cfg, "bpdu_guard")).unwrap_or(false),
            bpdu_guard_do_disable: parse_bool(field(&cfg, "bpdu_guard_do_disable"))
                .unwrap_or(false),
            root_guard: parse_bool(field(&cfg, "root_guard")).unwrap_or(false),
            bpdu_guard_shutdown: guard_shutdown(&appl),
            root_guard_active,
            name,
        });
    }
    Ok(json!({ "capability": cap, "ports": ports }))
}

#[derive(Debug, Deserialize)]
pub struct LoopPortInput {
    pub bpdu_guard: bool,
    pub bpdu_guard_do_disable: bool,
    pub root_guard: bool,
}

/// PUT /api/switching/loop-protection/ports/{name} — touches only the three
/// guard fields, never the rest of the STP_PORT row.
pub fn put_loop_port(plat: &mut dyn Platform, name: &str, input: &LoopPortInput) -> WriteResult {
    let _lock = store::feature_lock("stp");
    require_supported(plat)?;
    if !interface_exists(plat, name)? {
        return Err(WriteError::NotFound(format!("no such interface {name}")));
    }
    let as_bool = |v: bool| if v { "true" } else { "false" };
    plat.hset(
        CONFIG_DB,
        &format!("STP_PORT|{name}"),
        &[
            ("bpdu_guard", as_bool(input.bpdu_guard)),
            ("bpdu_guard_do_disable", as_bool(input.bpdu_guard_do_disable)),
            ("root_guard", as_bool(input.root_guard)),
        ],
    )
    .map_err(WriteError::Redis)
}

/// POST /api/switching/loop-protection/ports/{name}/recover — re-enable a
/// port BPDU guard admin-shut, mirroring `config interface startup`
/// (CONFIG_DB PORT admin_status back to up).
pub fn recover_port(plat: &mut dyn Platform, name: &str) -> WriteResult {
    let _lock = store::feature_lock("stp");
    require_supported(plat)?;
    if !interface_exists(plat, name)? {
        return Err(WriteError::NotFound(format!("no such interface {name}")));
    }
    let appl = row(plat, APPL_DB, &format!("STP_PORT_TABLE:{name}"));
    if guard_shutdown(&appl) != Some(true) {
        return Err(WriteError::Conflict(format!(
            "{name} is not BPDU-guard shutdown; nothing to recover"
        )));
    }
    let table = if name.starts_with("PortChannel") { "PORTCHANNEL" } else { "PORT" };
    plat.hset(CONFIG_DB, &format!("{table}|{name}"), &[("admin_status", "up")])
        .map_err(WriteError::Redis)
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::*;

    fn stp_platform() -> MemPlatform {
        let mut m = MemPlatform::new();
        // A 202505 community image built with INCLUDE_STP.
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202505.12'\n");
        m.seed(CONFIG_DB, "FEATURE|stp", &[("state", "enabled")]);
        m.seed(CONFIG_DB, "FEATURE|lldp", &[("state", "enabled")]);
        m.seed(CONFIG_DB, "FEATURE|bgp", &[("state", "enabled")]);
        m.seed(CONFIG_DB, "VLAN|Vlan10", &[("vlanid", "10")]);
        m.seed(CONFIG_DB, "VLAN|Vlan20", &[("vlanid", "20")]);
        m.seed(CONFIG_DB, "PORT|Ethernet0", &[("admin_status", "up")]);
        m.seed(CONFIG_DB, "PORT|Ethernet4", &[("admin_status", "up")]);
        m.seed(CONFIG_DB, "VLAN_MEMBER|Vlan10|Ethernet0", &[("tagging_mode", "untagged")]);
        m.seed(CONFIG_DB, "VLAN_MEMBER|Vlan20|Ethernet4", &[("tagging_mode", "tagged")]);
        m
    }

    fn h(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn worst_state_wins_and_bpdus_sum() {
        let mut d = PortOper::default();
        fold_port_oper(&mut d, &h(&[("port_state", "FORWARDING"), ("bpdu_sent", "5")]));
        assert_eq!(d.worst_state.as_deref(), Some("forwarding"));
        fold_port_oper(
            &mut d,
            &h(&[("port_state", "BLOCKING"), ("bpdu_sent", "3"), ("bpdu_received", "1")]),
        );
        assert_eq!(d.worst_state.as_deref(), Some("blocking"));
        assert_eq!(d.bpdu_sent, Some(8));
        assert_eq!(d.bpdu_received, Some(1));
        assert!(!d.root_guard_active);
        fold_port_oper(&mut d, &h(&[("root_guard_timer", "12")]));
        assert!(d.root_guard_active);
        // A better state later never improves the summary.
        fold_port_oper(&mut d, &h(&[("port_state", "forwarding")]));
        assert_eq!(d.worst_state.as_deref(), Some("blocking"));
    }

    #[test]
    fn timer_relation_enforced() {
        assert!(check_timer_relation(15, 2, 20).is_ok());
        // max_age too large for forward_delay.
        assert!(check_timer_relation(4, 2, 20).is_err());
        // max_age too small for hello_time.
        assert!(check_timer_relation(30, 10, 20).is_err());
        assert!(check_timer_relation(3, 2, 20).is_err()); // out of range
    }

    #[test]
    fn priorities_step_checked() {
        assert!(check_bridge_priority(0).is_ok());
        assert!(check_bridge_priority(61440).is_ok());
        assert!(check_bridge_priority(4095).is_err());
        assert!(check_bridge_priority(65536).is_err());
        assert!(check_port_priority(16).is_ok());
        assert!(check_port_priority(17).is_err());
        assert!(check_port_priority(241).is_err());
    }

    #[test]
    fn unsupported_image_gates_reads_and_writes() {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        m.seed(CONFIG_DB, "FEATURE|lldp", &[("state", "enabled")]);
        probe::invalidate();
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        assert_eq!(doc["vlans"], serde_json::json!([]));
        let err = put_global(
            &mut m,
            &GlobalInput {
                mode: Mode::Pvst,
                rootguard_timeout: None,
                forward_delay: None,
                hello_time: None,
                max_age: None,
                priority: None,
                region_name: None,
                revision: None,
                max_hops: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
    }

    #[test]
    fn enabling_seeds_vlans_and_ports_and_respects_instance_limit() {
        let mut m = stp_platform();
        probe::invalidate();
        put_global(
            &mut m,
            &GlobalInput {
                mode: Mode::Pvst,
                rootguard_timeout: None,
                forward_delay: None,
                hello_time: None,
                max_age: None,
                priority: None,
                region_name: None,
                revision: None,
                max_hops: None,
            },
        )
        .unwrap();
        assert_eq!(m.row(CONFIG_DB, "STP|GLOBAL").get("mode").unwrap(), "pvst");
        assert_eq!(m.row(CONFIG_DB, "STP|GLOBAL").get("forward_delay").unwrap(), "15");
        assert!(m.has_key(CONFIG_DB, "STP_VLAN|Vlan10"));
        assert!(m.has_key(CONFIG_DB, "STP_VLAN|Vlan20"));
        assert!(m.has_key(CONFIG_DB, "STP_PORT|Ethernet0"));
        assert!(m.has_key(CONFIG_DB, "STP_PORT|Ethernet4"));

        // Instance limit: a platform advertising one instance refuses two VLANs.
        let mut m = stp_platform();
        m.seed(STATE_DB, "STP_TABLE|GLOBAL", &[("max_stp_inst", "1")]);
        probe::invalidate();
        let err = put_global(
            &mut m,
            &GlobalInput {
                mode: Mode::Pvst,
                rootguard_timeout: None,
                forward_delay: None,
                hello_time: None,
                max_age: None,
                priority: None,
                region_name: None,
                revision: None,
                max_hops: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Unprocessable(_)));
    }

    #[test]
    fn mst_rejected_on_release_train_community() {
        let mut m = stp_platform();
        probe::invalidate();
        let err = put_global(
            &mut m,
            &GlobalInput {
                mode: Mode::Mst,
                rootguard_timeout: None,
                forward_delay: None,
                hello_time: None,
                max_age: None,
                priority: None,
                region_name: None,
                revision: None,
                max_hops: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Unprocessable(_)));
    }

    #[test]
    fn disable_removes_every_stp_table() {
        let mut m = stp_platform();
        m.seed(CONFIG_DB, "STP|GLOBAL", &[("mode", "pvst")]);
        m.seed(CONFIG_DB, "STP_VLAN|Vlan10", &[("enabled", "true")]);
        m.seed(CONFIG_DB, "STP_PORT|Ethernet0", &[("enabled", "true")]);
        m.seed(CONFIG_DB, "STP_VLAN_PORT|Vlan10|Ethernet0", &[("path_cost", "200")]);
        probe::invalidate();
        put_global(
            &mut m,
            &GlobalInput {
                mode: Mode::Disabled,
                rootguard_timeout: None,
                forward_delay: None,
                hello_time: None,
                max_age: None,
                priority: None,
                region_name: None,
                revision: None,
                max_hops: None,
            },
        )
        .unwrap();
        assert!(!m.has_key(CONFIG_DB, "STP|GLOBAL"));
        assert!(!m.has_key(CONFIG_DB, "STP_VLAN|Vlan10"));
        assert!(!m.has_key(CONFIG_DB, "STP_PORT|Ethernet0"));
        assert!(!m.has_key(CONFIG_DB, "STP_VLAN_PORT|Vlan10|Ethernet0"));
    }

    #[test]
    fn vlan_null_override_inherits_global() {
        let mut m = stp_platform();
        m.seed(CONFIG_DB, "STP|GLOBAL", &[("mode", "pvst")]);
        m.seed(CONFIG_DB, "STP_VLAN|Vlan10", &[("enabled", "true"), ("priority", "8192")]);
        probe::invalidate();
        let input: VlanInput =
            serde_json::from_str(r#"{"enabled": true, "priority": null}"#).unwrap();
        put_vlan(&mut m, 10, &input).unwrap();
        assert!(m.row(CONFIG_DB, "STP_VLAN|Vlan10").get("priority").is_none());
        // Omitted fields stay untouched.
        let input: VlanInput = serde_json::from_str(r#"{"enabled": false}"#).unwrap();
        m.seed(CONFIG_DB, "STP_VLAN|Vlan10", &[("hello_time", "3")]);
        put_vlan(&mut m, 10, &input).unwrap();
        let row = m.row(CONFIG_DB, "STP_VLAN|Vlan10");
        assert_eq!(row.get("enabled").unwrap(), "false");
        assert_eq!(row.get("hello_time").unwrap(), "3");
    }

    #[test]
    fn recover_requires_guard_shutdown() {
        let mut m = stp_platform();
        m.seed(CONFIG_DB, "STP|GLOBAL", &[("mode", "pvst")]);
        probe::invalidate();
        // Not shut → 409.
        let err = recover_port(&mut m, "Ethernet0").unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)), "{err:?}");
        // Guard-shut → PORT admin_status flips back up.
        m.seed(APPL_DB, "STP_PORT_TABLE:Ethernet0", &[("bpdu_guard_shutdown", "yes")]);
        m.seed(CONFIG_DB, "PORT|Ethernet0", &[("admin_status", "down")]);
        recover_port(&mut m, "Ethernet0").unwrap();
        assert_eq!(m.row(CONFIG_DB, "PORT|Ethernet0").get("admin_status").unwrap(), "up");
        // Unknown port → 404.
        let err = recover_port(&mut m, "Ethernet99").unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
    }

    #[test]
    fn loop_protection_put_touches_only_guard_fields() {
        let mut m = stp_platform();
        m.seed(CONFIG_DB, "STP|GLOBAL", &[("mode", "pvst")]);
        m.seed(CONFIG_DB, "STP_PORT|Ethernet0", &[("enabled", "true"), ("priority", "32")]);
        probe::invalidate();
        put_loop_port(
            &mut m,
            "Ethernet0",
            &LoopPortInput { bpdu_guard: true, bpdu_guard_do_disable: true, root_guard: false },
        )
        .unwrap();
        let row = m.row(CONFIG_DB, "STP_PORT|Ethernet0");
        assert_eq!(row.get("bpdu_guard").unwrap(), "true");
        assert_eq!(row.get("bpdu_guard_do_disable").unwrap(), "true");
        assert_eq!(row.get("root_guard").unwrap(), "false");
        // The rest of the row is untouched.
        assert_eq!(row.get("enabled").unwrap(), "true");
        assert_eq!(row.get("priority").unwrap(), "32");
    }

    #[test]
    fn get_summarizes_oper_state() {
        let mut m = stp_platform();
        m.seed(CONFIG_DB, "STP|GLOBAL", &[("mode", "pvst"), ("priority", "4096")]);
        m.seed(CONFIG_DB, "STP_VLAN|Vlan10", &[("enabled", "true")]);
        m.seed(
            APPL_DB,
            "STP_VLAN_TABLE:Vlan10",
            &[
                ("bridge_id", "8000AABB"),
                ("root_bridge_id", "8000AABB"),
                ("topology_change_count", "4"),
                ("last_topology_change", "120"),
            ],
        );
        m.seed(
            APPL_DB,
            "STP_VLAN_PORT_TABLE:Vlan10:Ethernet0",
            &[("port_state", "FORWARDING"), ("bpdu_sent", "10"), ("bpdu_received", "2")],
        );
        m.seed(
            APPL_DB,
            "STP_VLAN_PORT_TABLE:Vlan20:Ethernet0",
            &[("port_state", "BLOCKING"), ("bpdu_sent", "1")],
        );
        probe::invalidate();
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["modes_supported"], serde_json::json!(["pvst"]));
        assert_eq!(doc["global"]["mode"], "pvst");
        assert_eq!(doc["global"]["priority"], 4096);
        let vlan10 = doc["vlans"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["vlan_id"] == 10)
            .unwrap();
        assert_eq!(vlan10["is_root"], true);
        assert_eq!(vlan10["topology_change_count"], 4);
        assert_eq!(vlan10["last_topology_change_secs"], 120);
        let eth0 = doc["ports"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "Ethernet0")
            .unwrap();
        // Worst state across the two VLAN instances.
        assert_eq!(eth0["state"], "blocking");
        assert_eq!(eth0["bpdu_sent"], 11);
        assert_eq!(eth0["bpdu_received"], 2);
    }
}
