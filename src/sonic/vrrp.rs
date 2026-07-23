//! VRRP for the console's High Availability section.
//!
//! Backed by the `VRRP` CONFIG_DB table on images that ship vrrpd
//! (Enterprise SONiC; community builds generally lack it and report
//! unsupported). Group identity is (interface, vrid); the console defines a
//! virtual router across a switch pair and writes each switch's half
//! separately. Live master/backup state comes from STATE_DB `VRRP_TABLE`
//! rows, with `vtysh -c "show vrrp json"` as a fallback for FRR-vrrpd
//! images; both degrade to null, never an error.
//!
//! The stored `adv_interval` field is milliseconds rounded to centiseconds
//! (the granularity FRR-based vrrpd takes); enterprise CLIs store whole
//! seconds (1-255), so on read values under 100 are treated as seconds.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, field, keys, row, two_parts, Platform};
use super::switching::{parse_num, WriteError, WriteResult};
use super::{CONFIG_DB, STATE_DB};

const UNSUPPORTED: &str = "VRRP requires an image with vrrpd, e.g. Enterprise SONiC";

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

// ── GET /api/ha/vrrp ────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct GroupDoc {
    interface: String,
    vrid: u32,
    virtual_ips: Vec<String>,
    priority: u64,
    preempt: bool,
    adv_interval_ms: Option<u64>,
    version: Option<u64>,
    state: Option<&'static str>,
}

/// The stored `adv_interval` in ms (see the module comment for the
/// seconds-vs-ms heuristic). Pure.
pub fn adv_interval_ms(stored: Option<&str>) -> Option<u64> {
    let v: u64 = stored?.parse().ok()?;
    Some(if v < 100 { v * 1000 } else { v })
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    if !probe::current(plat).vrrp_supported() {
        return Ok(json!({ "capability": Capability::no(UNSUPPORTED), "groups": [] }));
    }
    let states = live_states(plat);
    let mut groups = Vec::new();
    for key in keys(plat, CONFIG_DB, "VRRP|*") {
        let Some((iface, vrid)) = two_parts(&key, "VRRP|") else { continue };
        let Ok(vrid) = vrid.parse::<u32>() else { continue };
        let iface = iface.to_string();
        let cfg = row(plat, CONFIG_DB, &key);
        let virtual_ips: Vec<String> = field(&cfg, "vip@")
            .or_else(|| field(&cfg, "vip"))
            .map(|s| {
                s.split(',').map(str::trim).filter(|v| !v.is_empty()).map(str::to_string).collect()
            })
            .unwrap_or_default();
        let preempt = field(&cfg, "pre_empt")
            .or_else(|| field(&cfg, "preempt"))
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "enabled" | "1"))
            .unwrap_or(true); // VRRP preempts by default
        groups.push(GroupDoc {
            state: states.get(&(iface.clone(), vrid)).copied(),
            interface: iface,
            vrid,
            virtual_ips,
            priority: parse_num(field(&cfg, "priority")).unwrap_or(100),
            preempt,
            adv_interval_ms: adv_interval_ms(field(&cfg, "adv_interval")),
            version: parse_num(field(&cfg, "version")).filter(|v| *v == 2 || *v == 3),
        });
    }
    groups.sort_by(|a, b| a.interface.cmp(&b.interface).then(a.vrid.cmp(&b.vrid)));
    Ok(json!({ "capability": Capability::yes(), "groups": groups }))
}

/// (interface, vrid) → live role. STATE_DB rows win; FRR-vrrpd images report
/// through vtysh instead. Both degrade to nothing.
fn live_states(plat: &mut dyn Platform) -> HashMap<(String, u32), &'static str> {
    let mut out = HashMap::new();
    for key in keys(plat, STATE_DB, "VRRP_TABLE|*") {
        let Some((iface, vrid)) = two_parts(&key, "VRRP_TABLE|") else { continue };
        let Ok(vrid) = vrid.parse::<u32>() else { continue };
        if let Some(s) = map_state(field(&row(plat, STATE_DB, &key), "state").unwrap_or("")) {
            out.insert((iface.to_string(), vrid), s);
        }
    }
    if let Ok(o) = plat.run("vtysh", &["-c", "show vrrp json"]) {
        if o.ok {
            for (iface, vrid, s) in parse_show_vrrp(&o.stdout) {
                out.entry((iface, vrid)).or_insert(s);
            }
        }
    }
    out
}

/// Map a daemon's state word onto the contract's enum. Pure, tolerant.
pub fn map_state(v: &str) -> Option<&'static str> {
    let v = v.to_ascii_lowercase();
    if v.contains("master") {
        Some("master")
    } else if v.contains("backup") {
        Some("backup")
    } else if v.contains("init") {
        Some("init")
    } else {
        None
    }
}

/// (interface, vrid, state) triples out of FRR's `show vrrp json`. Pure.
pub fn parse_show_vrrp(json_text: &str) -> Vec<(String, u32, &'static str)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json_text) else { return Vec::new() };
    let Some(arr) = v.as_array() else { return Vec::new() };
    let mut out = Vec::new();
    for g in arr {
        let (Some(iface), Some(vrid)) = (g["interface"].as_str(), g["vrid"].as_u64()) else {
            continue;
        };
        // The v4 sub-router speaks for the group unless it never left
        // Initialize while v6 did.
        let s4 = g["v4"]["status"].as_str().and_then(map_state);
        let s6 = g["v6"]["status"].as_str().and_then(map_state);
        let state = match (s4, s6) {
            (Some("init") | None, Some(s)) if s != "init" => Some(s),
            (s4, s6) => s4.or(s6),
        };
        if let Some(s) = state {
            out.push((iface.to_string(), vrid as u32, s));
        }
    }
    out
}

// ── PUT /api/ha/vrrp/{interface}/{vrid} ─────────────────────────────────────

/// One group minus its live state — an upsert for the (interface, vrid)
/// identity.
#[derive(Debug, Deserialize)]
pub struct GroupInput {
    pub interface: String,
    pub vrid: u32,
    pub virtual_ips: Vec<String>,
    pub priority: u32,
    pub preempt: bool,
    pub adv_interval_ms: Option<u32>,
    pub version: Option<u32>,
}

/// The L3 table an interface's addresses live in; None for names that can't
/// carry VRRP (also the injection guard — the name lands in CONFIG_DB keys).
fn l3_table(iface: &str) -> Option<&'static str> {
    for (prefix, table) in [
        ("Vlan", "VLAN_INTERFACE"),
        ("Ethernet", "INTERFACE"),
        ("PortChannel", "PORTCHANNEL_INTERFACE"),
    ] {
        if let Some(rest) = iface.strip_prefix(prefix) {
            if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
                return Some(table);
            }
        }
    }
    None
}

/// A virtual IP, bare or CIDR; the address part. Pure.
pub fn parse_vip(v: &str) -> Option<IpAddr> {
    let (ip, len) = match v.split_once('/') {
        Some((ip, len)) => (ip, Some(len)),
        None => (v, None),
    };
    let addr: IpAddr = ip.parse().ok()?;
    if let Some(len) = len {
        let len: u32 = len.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if len > max {
            return None;
        }
    }
    Some(addr)
}

/// Every address configured on this switch's interfaces.
fn own_addresses(plat: &mut dyn Platform) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for table in ["INTERFACE", "VLAN_INTERFACE", "PORTCHANNEL_INTERFACE", "LOOPBACK_INTERFACE"] {
        for key in keys(plat, CONFIG_DB, &format!("{table}|*|*")) {
            if let Some((_, cidr)) = two_parts(&key, &format!("{table}|")) {
                if let Some(ip) = cidr.split('/').next().and_then(|s| s.parse().ok()) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

pub fn put(plat: &mut dyn Platform, iface: &str, vrid: u32, input: &GroupInput) -> WriteResult {
    let _lock = store::feature_lock("vrrp");
    if input.interface != iface || input.vrid != vrid {
        return Err(bad("body interface/vrid must match the URL"));
    }
    if !(1..=255).contains(&vrid) {
        return Err(bad(format!("invalid vrid {vrid} (must be 1-255)")));
    }
    if !(1..=254).contains(&input.priority) {
        return Err(bad(format!("invalid priority {} (must be 1-254)", input.priority)));
    }
    if let Some(v) = input.version {
        if v != 2 && v != 3 {
            return Err(bad(format!("invalid version {v} (must be 2 or 3)")));
        }
    }
    if input.virtual_ips.is_empty() {
        return Err(bad("a VRRP group needs at least one virtual IP"));
    }
    let mut vip_addrs = Vec::new();
    for vip in &input.virtual_ips {
        let addr = parse_vip(vip).ok_or_else(|| bad(format!("invalid virtual IP {vip:?}")))?;
        if vip_addrs.contains(&addr) {
            return Err(bad(format!("duplicate virtual IP {vip}")));
        }
        vip_addrs.push(addr);
    }
    if vip_addrs.iter().any(|a| a.is_ipv4() != vip_addrs[0].is_ipv4()) {
        return Err(bad("virtual IPs must all be the same address family"));
    }
    // Round to the centisecond granularity the daemons take instead of
    // rejecting odd values; the range is a 422, not a 400.
    let adv = match input.adv_interval_ms {
        None => None,
        Some(ms) => {
            let rounded = (ms + 5) / 10 * 10;
            if !(100..=40950).contains(&rounded) {
                return Err(WriteError::Unprocessable(format!(
                    "adv_interval_ms {ms} is outside the supported 100-40950 ms range"
                )));
            }
            Some(rounded)
        }
    };

    if !probe::current(plat).vrrp_supported() {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    let table = l3_table(iface).ok_or_else(|| {
        bad(format!("interface {iface} cannot carry VRRP (expected an SVI, port, or port channel)"))
    })?;
    if keys(plat, CONFIG_DB, &format!("{table}|{iface}|*")).is_empty() {
        return Err(bad(format!("interface {iface} has no IP address configured")));
    }
    let own = own_addresses(plat);
    for (vip, addr) in input.virtual_ips.iter().zip(&vip_addrs) {
        if own.contains(addr) {
            return Err(bad(format!(
                "virtual IP {vip} is already one of this switch's interface addresses"
            )));
        }
    }

    // Replace the whole row so cleared optionals never linger.
    let key = format!("VRRP|{iface}|{vrid}");
    plat.del(CONFIG_DB, &key)?;
    let vips = input.virtual_ips.join(",");
    let mut fields: Vec<(&str, String)> = vec![
        ("vip@", vips),
        ("priority", input.priority.to_string()),
        ("pre_empt", if input.preempt { "True" } else { "False" }.to_string()),
    ];
    if let Some(ms) = adv {
        fields.push(("adv_interval", ms.to_string()));
    }
    if let Some(v) = input.version {
        fields.push(("version", v.to_string()));
    }
    let refs: Vec<(&str, &str)> = fields.iter().map(|(f, v)| (*f, v.as_str())).collect();
    plat.hset(CONFIG_DB, &key, &refs)?;
    Ok(())
}

// ── DELETE /api/ha/vrrp/{interface}/{vrid} ──────────────────────────────────

pub fn delete(plat: &mut dyn Platform, iface: &str, vrid: u32) -> WriteResult {
    let _lock = store::feature_lock("vrrp");
    let key = format!("VRRP|{iface}|{vrid}");
    if !plat.exists(CONFIG_DB, &key)? {
        return Err(WriteError::NotFound(format!("no VRRP group {vrid} on {iface}")));
    }
    plat.del(CONFIG_DB, &key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::super::store::CmdOutput;
    use super::*;

    fn platform() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        m.seed(CONFIG_DB, "FEATURE|vrrp", &[("state", "enabled")]);
        m.seed(CONFIG_DB, "VLAN_INTERFACE|Vlan10", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "VLAN_INTERFACE|Vlan10|10.0.10.2/24", &[("NULL", "NULL")]);
        m
    }

    fn group() -> GroupInput {
        GroupInput {
            interface: "Vlan10".into(),
            vrid: 1,
            virtual_ips: vec!["10.0.10.1".into()],
            priority: 200,
            preempt: true,
            adv_interval_ms: Some(1000),
            version: None,
        }
    }

    #[test]
    fn unsupported_without_vrrpd() {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        assert_eq!(doc["groups"], json!([]));
        let err = put(&mut m, "Vlan10", 1, &group()).unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
    }

    #[test]
    fn put_writes_group_row() {
        let mut m = platform();
        put(&mut m, "Vlan10", 1, &group()).unwrap();
        let row = m.row(CONFIG_DB, "VRRP|Vlan10|1");
        assert_eq!(row.get("vip@").unwrap(), "10.0.10.1");
        assert_eq!(row.get("priority").unwrap(), "200");
        assert_eq!(row.get("pre_empt").unwrap(), "True");
        assert_eq!(row.get("adv_interval").unwrap(), "1000");
        assert!(!row.contains_key("version"));
        // Odd intervals round to centiseconds instead of failing.
        let mut odd = group();
        odd.adv_interval_ms = Some(996);
        put(&mut m, "Vlan10", 1, &odd).unwrap();
        assert_eq!(m.row(CONFIG_DB, "VRRP|Vlan10|1").get("adv_interval").unwrap(), "1000");
    }

    #[test]
    fn put_validation() {
        let mut m = platform();
        let mut mismatch = group();
        mismatch.vrid = 2;
        assert!(matches!(
            put(&mut m, "Vlan10", 1, &mismatch).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        let mut bad_vrid = group();
        bad_vrid.vrid = 300;
        assert!(matches!(
            put(&mut m, "Vlan10", 300, &bad_vrid).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        let mut bad_priority = group();
        bad_priority.priority = 255;
        let mut no_vips = group();
        no_vips.virtual_ips.clear();
        let mut bad_vip = group();
        bad_vip.virtual_ips = vec!["not-an-ip".into()];
        let mut colliding = group();
        colliding.virtual_ips = vec!["10.0.10.2".into()]; // the SVI's own address
        let mut mixed = group();
        mixed.virtual_ips = vec!["10.0.10.1".into(), "fd00::1".into()];
        let mut bad_version = group();
        bad_version.version = Some(4);
        for i in [bad_priority, no_vips, bad_vip, colliding, mixed, bad_version] {
            let err = put(&mut m, "Vlan10", 1, &i).unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{err:?}");
        }
        // Interface without an address / unknown kinds.
        let mut other = group();
        other.interface = "Vlan99".into();
        assert!(matches!(put(&mut m, "Vlan99", 1, &other).unwrap_err(), WriteError::BadRequest(_)));
        let mut mgmt = group();
        mgmt.interface = "eth0".into();
        assert!(matches!(put(&mut m, "eth0", 1, &mgmt).unwrap_err(), WriteError::BadRequest(_)));
        // Out-of-range interval is a 422.
        let mut slow = group();
        slow.adv_interval_ms = Some(90000);
        assert!(matches!(
            put(&mut m, "Vlan10", 1, &slow).unwrap_err(),
            WriteError::Unprocessable(_)
        ));
    }

    #[test]
    fn get_maps_rows_and_state() {
        let mut m = platform();
        put(&mut m, "Vlan10", 1, &group()).unwrap();
        // A foreign row written in enterprise style: seconds + preempt word.
        m.seed(
            CONFIG_DB,
            "VRRP|Vlan20|5",
            &[("vip", "10.0.20.1/24"), ("priority", "90"), ("pre_empt", "False"), ("adv_interval", "1"), ("version", "3")],
        );
        m.seed(CONFIG_DB, "VLAN_INTERFACE|Vlan20|10.0.20.2/24", &[("NULL", "NULL")]);
        m.seed(STATE_DB, "VRRP_TABLE|Vlan10|1", &[("state", "Master")]);
        m.on_cmd(
            &["vtysh", "-c", "show vrrp json"],
            CmdOutput {
                ok: true,
                stdout: r#"[{"vrid":5,"interface":"Vlan20","v4":{"status":"Backup"},"v6":{"status":"Initialize"}}]"#.into(),
                stderr: String::new(),
            },
        );
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        let groups = doc["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["interface"], "Vlan10");
        assert_eq!(groups[0]["vrid"], 1);
        assert_eq!(groups[0]["virtual_ips"], json!(["10.0.10.1"]));
        assert_eq!(groups[0]["priority"], 200);
        assert_eq!(groups[0]["preempt"], true);
        assert_eq!(groups[0]["adv_interval_ms"], 1000);
        assert_eq!(groups[0]["state"], "master");
        assert_eq!(groups[1]["interface"], "Vlan20");
        assert_eq!(groups[1]["virtual_ips"], json!(["10.0.20.1/24"]));
        assert_eq!(groups[1]["preempt"], false);
        assert_eq!(groups[1]["adv_interval_ms"], 1000); // stored "1" = 1 second
        assert_eq!(groups[1]["version"], 3);
        assert_eq!(groups[1]["state"], "backup"); // via vtysh fallback
    }

    #[test]
    fn delete_group() {
        let mut m = platform();
        put(&mut m, "Vlan10", 1, &group()).unwrap();
        delete(&mut m, "Vlan10", 1).unwrap();
        assert!(!m.has_key(CONFIG_DB, "VRRP|Vlan10|1"));
        assert!(matches!(delete(&mut m, "Vlan10", 1).unwrap_err(), WriteError::NotFound(_)));
    }

    #[test]
    fn show_vrrp_parsing() {
        let parsed = parse_show_vrrp(
            r#"[{"vrid":1,"interface":"Vlan10","v4":{"status":"Master"},"v6":{"status":"Initialize"}},
                {"vrid":2,"interface":"Vlan20","v4":{"status":"Initialize"},"v6":{"status":"Backup"}}]"#,
        );
        assert_eq!(parsed[0], ("Vlan10".to_string(), 1, "master"));
        assert_eq!(parsed[1], ("Vlan20".to_string(), 2, "backup"));
        assert!(parse_show_vrrp("not json").is_empty());
    }
}
