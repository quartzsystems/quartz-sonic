//! Read-only switching state for the console's Configure → Switching pages:
//! ports, port channels, and VLANs, assembled from CONFIG_DB / STATE_DB /
//! COUNTERS_DB.
//!
//! The collectors degrade per-field, never per-endpoint: a missing STATE_DB
//! row, an absent counters entry, or a garbled value produces that field's
//! documented null/default, and every object present in CONFIG_DB still
//! appears in the response. Only an unreachable CONFIG_DB returns an error
//! (the management API turns that into an error ProxyResponse). All redis
//! reads run inside the management API's spawn_blocking.

use std::cmp::Ordering;
use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;

use super::{connection, hgetall_on, scan_keys, CONFIG_DB, COUNTERS_DB, STATE_DB};

// ── ports ───────────────────────────────────────────────────────────────────

/// One row of `GET /api/switching/ports` — field shapes are a contract with
/// the console's Ports page.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Port {
    pub name: String,
    pub alias: Option<String>,
    pub description: Option<String>,
    pub admin_status: String,
    pub oper_status: String,
    pub speed_mbps: Option<u64>,
    pub fec: Option<String>,
    pub mtu: Option<u64>,
    pub vlan_mode: Option<&'static str>,
    pub untagged_vlan: Option<u32>,
    pub tagged_vlans: Vec<u32>,
    pub rx_err: Option<u64>,
    pub tx_err: Option<u64>,
    pub rx_drops: Option<u64>,
    pub tx_drops: Option<u64>,
}

/// Every CONFIG_DB port, fully assembled and naturally sorted. Errors only
/// when CONFIG_DB itself is unreachable.
pub fn ports() -> Result<Vec<Port>> {
    let mut cfg = connection(CONFIG_DB)?;
    let port_keys = scan_keys(&mut cfg, "PORT|*")?;
    // Member name → its VLAN memberships. Keys whose member is a PortChannel
    // simply never match a physical port name below.
    let mut vlan_rows: HashMap<String, Vec<(u32, String)>> = HashMap::new();
    for key in scan_keys(&mut cfg, "VLAN_MEMBER|*").unwrap_or_default() {
        let Some((vlan, member)) = member_parts(&key, "VLAN_MEMBER|") else { continue };
        let Some(id) = vlan_id_from_name(vlan) else { continue };
        let mode = field(&hgetall_on(&mut cfg, &key), "tagging_mode")
            .unwrap_or("untagged") // SONiC's default tagging_mode
            .to_string();
        vlan_rows.entry(member.to_string()).or_default().push((id, mode));
    }
    let mut state = connection(STATE_DB).ok();
    let counters = port_counters();
    let mut out = Vec::with_capacity(port_keys.len());
    for key in &port_keys {
        let Some(name) = key_suffix(key, "PORT|") else { continue };
        let cfg_row = hgetall_on(&mut cfg, key);
        let state_row = state_row(&mut state, &format!("PORT_TABLE|{name}"));
        let rows = vlan_rows.get(name).map(Vec::as_slice).unwrap_or(&[]);
        out.push(port_from(name, &cfg_row, &state_row, counters.get(name), rows));
    }
    out.sort_by(|a, b| natural_cmp(&a.name, &b.name));
    Ok(out)
}

/// Assemble one port from its CONFIG_DB row, STATE_DB row, counters hash
/// (None = no COUNTERS entry), and VLAN membership rows. Pure.
pub fn port_from(
    name: &str,
    cfg: &HashMap<String, String>,
    state: &HashMap<String, String>,
    counters: Option<&HashMap<String, String>>,
    vlan_rows: &[(u32, String)],
) -> Port {
    let (vlan_mode, untagged_vlan, tagged_vlans) = vlan_mode_of(vlan_rows);
    // A field missing from a present counters hash reads as 0 — platforms
    // differ in which SAI counters they populate.
    let stat = |key: &str| counters.map(|h| parse_num(field(h, key)).unwrap_or(0));
    Port {
        name: name.to_string(),
        alias: field(cfg, "alias").map(str::to_string),
        description: field(cfg, "description").map(str::to_string),
        admin_status: field(cfg, "admin_status").unwrap_or("down").to_string(),
        oper_status: field(state, "oper_status").unwrap_or("unknown").to_string(),
        speed_mbps: parse_num(field(state, "speed")).or_else(|| parse_num(field(cfg, "speed"))),
        fec: field(cfg, "fec").map(str::to_string),
        mtu: parse_num(field(cfg, "mtu")),
        vlan_mode,
        untagged_vlan,
        tagged_vlans,
        rx_err: stat("SAI_PORT_STAT_IF_IN_ERRORS"),
        tx_err: stat("SAI_PORT_STAT_IF_OUT_ERRORS"),
        rx_drops: stat("SAI_PORT_STAT_IF_IN_DISCARDS"),
        tx_drops: stat("SAI_PORT_STAT_IF_OUT_DISCARDS"),
    }
}

/// Fold a port's VLAN_MEMBER rows (vlan id, tagging_mode) into the contract's
/// (vlan_mode, untagged_vlan, tagged_vlans) triple: untagged membership only
/// → "access", any tagged membership → "trunk" (untagged_vlan then holds the
/// native VLAN), no membership at all → "routed". Rows with an unrecognizable
/// tagging_mode are ignored; when nothing recognizable remains the mode is
/// unknowable → None.
pub fn vlan_mode_of(rows: &[(u32, String)]) -> (Option<&'static str>, Option<u32>, Vec<u32>) {
    if rows.is_empty() {
        return (Some("routed"), None, Vec::new());
    }
    let untagged = rows
        .iter()
        .filter(|(_, m)| m == "untagged")
        .map(|(id, _)| *id)
        .min();
    let mut tagged: Vec<u32> = rows
        .iter()
        .filter(|(_, m)| m == "tagged")
        .map(|(id, _)| *id)
        .collect();
    tagged.sort_unstable();
    tagged.dedup();
    let mode = if !tagged.is_empty() {
        Some("trunk")
    } else if untagged.is_some() {
        Some("access")
    } else {
        None
    };
    (mode, untagged, tagged)
}

/// Port name → COUNTERS:<oid> hash for every port with a non-empty counters
/// entry (via COUNTERS_PORT_NAME_MAP). Empty when COUNTERS_DB is unreachable,
/// so every port's error/drop fields degrade to null together.
fn port_counters() -> HashMap<String, HashMap<String, String>> {
    let Ok(mut conn) = connection(COUNTERS_DB) else {
        return HashMap::new();
    };
    hgetall_on(&mut conn, "COUNTERS_PORT_NAME_MAP")
        .into_iter()
        .filter_map(|(name, oid)| {
            let h = hgetall_on(&mut conn, &format!("COUNTERS:{oid}"));
            (!h.is_empty()).then_some((name, h))
        })
        .collect()
}

// ── port channels ───────────────────────────────────────────────────────────

/// One member of a port channel.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortChannelMember {
    pub name: String,
    pub oper_status: String,
    pub selected: Option<bool>,
}

/// One row of `GET /api/switching/port-channels`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortChannel {
    pub name: String,
    pub protocol: &'static str,
    pub admin_status: String,
    pub oper_status: String,
    pub mtu: Option<u64>,
    pub min_links: Option<u64>,
    pub fallback: bool,
    pub fast_rate: bool,
    pub members: Vec<PortChannelMember>,
}

/// Every CONFIG_DB port channel with member state, naturally sorted. Errors
/// only when CONFIG_DB itself is unreachable.
pub fn port_channels() -> Result<Vec<PortChannel>> {
    let mut cfg = connection(CONFIG_DB)?;
    let pc_keys = scan_keys(&mut cfg, "PORTCHANNEL|*")?;
    let mut member_names: HashMap<String, Vec<String>> = HashMap::new();
    for key in scan_keys(&mut cfg, "PORTCHANNEL_MEMBER|*").unwrap_or_default() {
        if let Some((pc, port)) = member_parts(&key, "PORTCHANNEL_MEMBER|") {
            member_names.entry(pc.to_string()).or_default().push(port.to_string());
        }
    }
    let mut state = connection(STATE_DB).ok();
    let mut out = Vec::with_capacity(pc_keys.len());
    for key in &pc_keys {
        let Some(name) = key_suffix(key, "PORTCHANNEL|") else { continue };
        let row = hgetall_on(&mut cfg, key);
        let is_static = parse_bool(field(&row, "static")).unwrap_or(false);
        let mut ports = member_names.remove(name).unwrap_or_default();
        ports.sort_by(|a, b| natural_cmp(a, b));
        let members = ports
            .into_iter()
            .map(|port| {
                // Selection is only meaningful under LACP, and only when the
                // platform actually published it — never guessed.
                let selected = if is_static {
                    None
                } else {
                    lacp_selected(&state_row(&mut state, &format!("LAG_MEMBER_TABLE|{name}|{port}")))
                };
                PortChannelMember {
                    oper_status: member_oper(&mut state, &port),
                    name: port,
                    selected,
                }
            })
            .collect();
        out.push(PortChannel {
            name: name.to_string(),
            protocol: if is_static { "static" } else { "lacp" },
            admin_status: field(&row, "admin_status").unwrap_or("down").to_string(),
            oper_status: field(&state_row(&mut state, &format!("LAG_TABLE|{name}")), "oper_status")
                .unwrap_or("unknown")
                .to_string(),
            mtu: parse_num(field(&row, "mtu")),
            min_links: parse_num(field(&row, "min_links")),
            fallback: parse_bool(field(&row, "fallback")).unwrap_or(false),
            fast_rate: parse_bool(field(&row, "fast_rate")).unwrap_or(false),
            members,
        });
    }
    out.sort_by(|a, b| natural_cmp(&a.name, &b.name));
    Ok(out)
}

/// LACP selection from a STATE_DB LAG_MEMBER_TABLE row: teamd publishes
/// `status` enabled/disabled. Anything else is unknown → None, never a guess.
pub fn lacp_selected(row: &HashMap<String, String>) -> Option<bool> {
    match field(row, "status")? {
        "enabled" => Some(true),
        "disabled" => Some(false),
        _ => None,
    }
}

// ── VLANs ───────────────────────────────────────────────────────────────────

/// One member of a VLAN — the name can be a port or a PortChannel.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VlanMember {
    pub name: String,
    pub tagging: &'static str,
}

/// One row of `GET /api/switching/vlans`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Vlan {
    pub vlan_id: u32,
    pub name: String,
    pub description: Option<String>,
    pub ip_addresses: Vec<String>,
    pub dhcp_helpers: Vec<String>,
    pub members: Vec<VlanMember>,
}

/// Every CONFIG_DB VLAN with members and L3 config, sorted by vlan id. Errors
/// only when CONFIG_DB itself is unreachable.
pub fn vlans() -> Result<Vec<Vlan>> {
    let mut cfg = connection(CONFIG_DB)?;
    let vlan_keys = scan_keys(&mut cfg, "VLAN|*")?;
    // Two-part VLAN_INTERFACE keys carry attributes; only the three-part
    // VLAN_INTERFACE|VlanN|<cidr> keys carry an address.
    let mut ips: HashMap<String, Vec<String>> = HashMap::new();
    for key in scan_keys(&mut cfg, "VLAN_INTERFACE|*").unwrap_or_default() {
        if let Some((vlan, cidr)) = member_parts(&key, "VLAN_INTERFACE|") {
            ips.entry(vlan.to_string()).or_default().push(cidr.to_string());
        }
    }
    let mut members: HashMap<String, Vec<VlanMember>> = HashMap::new();
    for key in scan_keys(&mut cfg, "VLAN_MEMBER|*").unwrap_or_default() {
        let Some((vlan, member)) = member_parts(&key, "VLAN_MEMBER|") else { continue };
        let tagging = match field(&hgetall_on(&mut cfg, &key), "tagging_mode") {
            Some("tagged") => "tagged",
            _ => "untagged", // SONiC's default tagging_mode
        };
        members
            .entry(vlan.to_string())
            .or_default()
            .push(VlanMember { name: member.to_string(), tagging });
    }
    let mut out = Vec::with_capacity(vlan_keys.len());
    for key in &vlan_keys {
        let Some(name) = key_suffix(key, "VLAN|") else { continue };
        let row = hgetall_on(&mut cfg, key);
        // `vlanid` first, the VlanN key as fallback; a key that yields
        // neither has no usable identity and is skipped.
        let Some(vlan_id) = parse_num(field(&row, "vlanid"))
            .and_then(|n| u32::try_from(n).ok())
            .or_else(|| vlan_id_from_name(name))
        else {
            continue;
        };
        let mut addrs = ips.remove(name).unwrap_or_default();
        addrs.sort();
        let mut mems = members.remove(name).unwrap_or_default();
        mems.sort_by(|a, b| natural_cmp(&a.name, &b.name));
        out.push(Vlan {
            vlan_id,
            name: name.to_string(),
            description: field(&row, "description").map(str::to_string),
            ip_addresses: addrs,
            dhcp_helpers: dhcp_helpers(&row),
            members: mems,
        });
    }
    out.sort_by_key(|v| v.vlan_id);
    Ok(out)
}

/// The VLAN's `dhcp_servers` list — stored as a comma-joined `dhcp_servers@`
/// field in the redis encoding of CONFIG_DB lists (plain name tolerated too).
pub fn dhcp_helpers(row: &HashMap<String, String>) -> Vec<String> {
    field(row, "dhcp_servers@")
        .or_else(|| field(row, "dhcp_servers"))
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// "Vlan10" → 10. None when the name isn't a VlanN key.
pub fn vlan_id_from_name(name: &str) -> Option<u32> {
    name.strip_prefix("Vlan")?.parse().ok()
}

// ── shared helpers ──────────────────────────────────────────────────────────

/// Order interface names naturally: digit runs compare by numeric value,
/// everything else byte-wise — Ethernet4 < Ethernet12, Eth1/2 < Eth1/10.
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    loop {
        match (a.first(), b.first()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(&x), Some(&y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let (na, rest_a) = take_number(a);
                let (nb, rest_b) = take_number(b);
                match na.cmp(&nb) {
                    Ordering::Equal => (a, b) = (rest_a, rest_b),
                    other => return other,
                }
            }
            (Some(&x), Some(&y)) => match x.cmp(&y) {
                Ordering::Equal => (a, b) = (&a[1..], &b[1..]),
                other => return other,
            },
        }
    }
}

/// Split a leading digit run off `s` as its numeric value (saturating —
/// interface numbers are nowhere near u64::MAX, but garbage shouldn't panic).
fn take_number(s: &[u8]) -> (u64, &[u8]) {
    let end = s.iter().position(|c| !c.is_ascii_digit()).unwrap_or(s.len());
    let n = s[..end]
        .iter()
        .fold(0u64, |acc, &c| acc.saturating_mul(10).saturating_add(u64::from(c - b'0')));
    (n, &s[end..])
}

/// Numeric CONFIG_DB/STATE_DB values arrive as strings; None on absence or
/// garbage.
pub fn parse_num(v: Option<&str>) -> Option<u64> {
    v?.parse().ok()
}

/// Boolean CONFIG_DB values ("true"/"false", any case); None on anything else.
pub fn parse_bool(v: Option<&str>) -> Option<bool> {
    match v?.to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// A hash field, trimmed; None when absent or empty.
fn field<'a>(h: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    h.get(key).map(|v| v.trim()).filter(|v| !v.is_empty())
}

/// "Ethernet0" from "PORT|Ethernet0". None on an empty suffix.
fn key_suffix<'a>(key: &'a str, prefix: &str) -> Option<&'a str> {
    key.strip_prefix(prefix).filter(|s| !s.is_empty())
}

/// ("Vlan10", "Ethernet0") from "VLAN_MEMBER|Vlan10|Ethernet0" given the
/// "VLAN_MEMBER|" prefix. None unless both parts are non-empty.
fn member_parts<'a>(key: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let (a, b) = key.strip_prefix(prefix)?.split_once('|')?;
    (!a.is_empty() && !b.is_empty()).then_some((a, b))
}

/// A STATE_DB row, or an empty hash when STATE_DB is unreachable — every
/// consumer treats an empty row as "state unknown".
fn state_row(conn: &mut Option<redis::Connection>, key: &str) -> HashMap<String, String> {
    conn.as_mut().map(|c| hgetall_on(c, key)).unwrap_or_default()
}

/// Oper status for a member name: PORT_TABLE for ports, LAG_TABLE for
/// PortChannels (member names can be either).
fn member_oper(state: &mut Option<redis::Connection>, name: &str) -> String {
    let table = if name.starts_with("PortChannel") { "LAG_TABLE" } else { "PORT_TABLE" };
    field(&state_row(state, &format!("{table}|{name}")), "oper_status")
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn rows(pairs: &[(u32, &str)]) -> Vec<(u32, String)> {
        pairs.iter().map(|(id, m)| (*id, m.to_string())).collect()
    }

    #[test]
    fn natural_sort_orders_by_numeric_suffix() {
        let mut names = vec!["Ethernet12", "Ethernet0", "Ethernet4", "Ethernet100"];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(names, vec!["Ethernet0", "Ethernet4", "Ethernet12", "Ethernet100"]);
    }

    #[test]
    fn natural_sort_handles_multi_segment_and_mixed_names() {
        assert_eq!(natural_cmp("Eth1/2", "Eth1/10"), Ordering::Less);
        assert_eq!(natural_cmp("Eth2/1", "Eth10/1"), Ordering::Less);
        assert_eq!(natural_cmp("Ethernet0", "Ethernet0"), Ordering::Equal);
        assert_eq!(natural_cmp("Ethernet", "Ethernet0"), Ordering::Less);
        assert_eq!(natural_cmp("Ethernet4", "PortChannel1"), Ordering::Less);
    }

    #[test]
    fn vlan_mode_untagged_only_is_access() {
        let (mode, untagged, tagged) = vlan_mode_of(&rows(&[(10, "untagged")]));
        assert_eq!(mode, Some("access"));
        assert_eq!(untagged, Some(10));
        assert!(tagged.is_empty());
    }

    #[test]
    fn vlan_mode_any_tagged_is_trunk_with_native() {
        let (mode, untagged, tagged) =
            vlan_mode_of(&rows(&[(30, "tagged"), (10, "untagged"), (20, "tagged")]));
        assert_eq!(mode, Some("trunk"));
        assert_eq!(untagged, Some(10));
        assert_eq!(tagged, vec![20, 30]);
        // Trunk without a native VLAN is fine too.
        let (mode, untagged, _) = vlan_mode_of(&rows(&[(20, "tagged")]));
        assert_eq!(mode, Some("trunk"));
        assert_eq!(untagged, None);
    }

    #[test]
    fn vlan_mode_no_membership_is_routed() {
        assert_eq!(vlan_mode_of(&[]), (Some("routed"), None, Vec::new()));
    }

    #[test]
    fn vlan_mode_unrecognizable_rows_derive_nothing() {
        let (mode, untagged, tagged) = vlan_mode_of(&rows(&[(10, "sideways")]));
        assert_eq!(mode, None);
        assert_eq!(untagged, None);
        assert!(tagged.is_empty());
    }

    #[test]
    fn numeric_strings_parse_defensively() {
        assert_eq!(parse_num(Some("9100")), Some(9100));
        assert_eq!(parse_num(Some("100000")), Some(100_000));
        assert_eq!(parse_num(Some("9100 bytes")), None);
        assert_eq!(parse_num(Some("-1")), None);
        assert_eq!(parse_num(None), None);
    }

    #[test]
    fn boolean_strings_parse_defensively() {
        assert_eq!(parse_bool(Some("true")), Some(true));
        assert_eq!(parse_bool(Some("False")), Some(false));
        assert_eq!(parse_bool(Some("yes")), None);
        assert_eq!(parse_bool(None), None);
    }

    #[test]
    fn port_assembles_from_all_sources() {
        let p = port_from(
            "Ethernet0",
            &h(&[
                ("alias", "Eth1/1"),
                ("description", "uplink spine1"),
                ("admin_status", "up"),
                ("speed", "40000"),
                ("fec", "rs"),
                ("mtu", "9100"),
            ]),
            &h(&[("oper_status", "up"), ("speed", "100000")]),
            Some(&h(&[
                ("SAI_PORT_STAT_IF_IN_ERRORS", "3"),
                ("SAI_PORT_STAT_IF_OUT_ERRORS", "0"),
                ("SAI_PORT_STAT_IF_IN_DISCARDS", "7"),
                ("SAI_PORT_STAT_IF_OUT_DISCARDS", "1"),
            ])),
            &rows(&[(10, "untagged"), (20, "tagged")]),
        );
        assert_eq!(p.alias.as_deref(), Some("Eth1/1"));
        assert_eq!(p.admin_status, "up");
        assert_eq!(p.oper_status, "up");
        // STATE_DB speed wins over the CONFIG_DB one.
        assert_eq!(p.speed_mbps, Some(100_000));
        assert_eq!(p.mtu, Some(9100));
        assert_eq!(p.vlan_mode, Some("trunk"));
        assert_eq!(p.untagged_vlan, Some(10));
        assert_eq!(p.tagged_vlans, vec![20]);
        assert_eq!(p.rx_err, Some(3));
        assert_eq!(p.tx_drops, Some(1));
    }

    #[test]
    fn port_degrades_field_by_field() {
        let p = port_from("Ethernet4", &HashMap::new(), &HashMap::new(), None, &[]);
        assert_eq!(p.admin_status, "down"); // SONiC default
        assert_eq!(p.oper_status, "unknown");
        assert_eq!(p.speed_mbps, None);
        assert_eq!(p.alias, None);
        assert_eq!(p.mtu, None);
        assert_eq!(p.vlan_mode, Some("routed"));
        // No counters entry → null, not zero.
        assert_eq!(p.rx_err, None);
        assert_eq!(p.tx_err, None);
        // CONFIG_DB speed used when STATE_DB has none; garbage numbers → null.
        let p = port_from(
            "Ethernet8",
            &h(&[("speed", "25000"), ("mtu", "jumbo")]),
            &HashMap::new(),
            Some(&h(&[("SAI_PORT_STAT_IF_IN_ERRORS", "2")])),
            &[],
        );
        assert_eq!(p.speed_mbps, Some(25_000));
        assert_eq!(p.mtu, None);
        // A present counters entry with a missing field reads as 0.
        assert_eq!(p.rx_err, Some(2));
        assert_eq!(p.tx_err, Some(0));
    }

    #[test]
    fn port_serializes_to_the_contract_shape() {
        let v = serde_json::to_value(port_from(
            "Ethernet4",
            &HashMap::new(),
            &HashMap::new(),
            None,
            &[],
        ))
        .unwrap();
        assert_eq!(v["name"], "Ethernet4");
        assert!(v["alias"].is_null());
        assert!(v["speed_mbps"].is_null());
        assert!(v["rx_err"].is_null());
        assert_eq!(v["vlan_mode"], "routed");
        assert_eq!(v["tagged_vlans"], serde_json::json!([]));
    }

    #[test]
    fn lacp_selection_is_never_guessed() {
        assert_eq!(lacp_selected(&h(&[("status", "enabled")])), Some(true));
        assert_eq!(lacp_selected(&h(&[("status", "disabled")])), Some(false));
        assert_eq!(lacp_selected(&h(&[("status", "flapping")])), None);
        assert_eq!(lacp_selected(&HashMap::new()), None);
    }

    #[test]
    fn dhcp_helper_lists_split_on_commas() {
        assert_eq!(
            dhcp_helpers(&h(&[("dhcp_servers@", "10.0.0.5,10.0.0.6")])),
            vec!["10.0.0.5", "10.0.0.6"]
        );
        // Plain field name tolerated; blanks dropped.
        assert_eq!(dhcp_helpers(&h(&[("dhcp_servers", " 10.0.0.5 ,")])), vec!["10.0.0.5"]);
        assert_eq!(dhcp_helpers(&HashMap::new()), Vec::<String>::new());
    }

    #[test]
    fn vlan_ids_parse_from_key_names() {
        assert_eq!(vlan_id_from_name("Vlan10"), Some(10));
        assert_eq!(vlan_id_from_name("Vlan4094"), Some(4094));
        assert_eq!(vlan_id_from_name("Vlan"), None);
        assert_eq!(vlan_id_from_name("Ethernet0"), None);
    }

    #[test]
    fn keys_split_into_their_parts() {
        assert_eq!(key_suffix("PORT|Ethernet0", "PORT|"), Some("Ethernet0"));
        assert_eq!(key_suffix("PORT|", "PORT|"), None);
        assert_eq!(
            member_parts("VLAN_MEMBER|Vlan10|Ethernet0", "VLAN_MEMBER|"),
            Some(("Vlan10", "Ethernet0"))
        );
        // Two-part VLAN_INTERFACE attribute keys carry no address.
        assert_eq!(member_parts("VLAN_INTERFACE|Vlan10", "VLAN_INTERFACE|"), None);
        assert_eq!(
            member_parts("VLAN_INTERFACE|Vlan10|10.0.10.1/24", "VLAN_INTERFACE|"),
            Some(("Vlan10", "10.0.10.1/24"))
        );
    }
}
