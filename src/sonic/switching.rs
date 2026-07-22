//! Switching state and configuration for the console's Configure → Switching
//! pages: ports, port channels, and VLANs, read from CONFIG_DB / APPL_DB /
//! STATE_DB / COUNTERS_DB and written back to CONFIG_DB.
//!
//! Port and LAG oper state comes from APPL_DB (`PORT_TABLE:<name>` /
//! `LAG_TABLE:<name>`, colon-separated keys — the same source `show
//! interfaces status` uses), with the STATE_DB `|`-separated rows as a
//! fallback; STATE_DB's PORT_TABLE mostly carries transceiver/init state.
//!
//! The read collectors degrade per-field, never per-endpoint: a missing
//! APPL_DB/STATE_DB row, an absent counters entry, or a garbled value
//! produces that field's documented null/default, and every object present
//! in CONFIG_DB still appears in the response. Only an unreachable CONFIG_DB
//! returns an error (the management API turns that into an error
//! ProxyResponse).
//!
//! The write operations converge CONFIG_DB toward the request's desired
//! state: lists in a payload are full sets, diffed against the current rows
//! so unchanged rows are never touched. Validation failures surface as
//! [`WriteError::BadRequest`]/[`WriteError::NotFound`]/
//! [`WriteError::Unprocessable`] before anything is written. All redis access
//! runs inside the management API's spawn_blocking.

use std::cmp::Ordering;
use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};

use super::{connection, hgetall_on, scan_keys, APPL_DB, CONFIG_DB, COUNTERS_DB, STATE_DB};

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
    /// Speeds the platform/SDK reports the port can run, from STATE_DB
    /// `supported_speeds`. None (→ JSON null, never []) when unpublished so
    /// the console falls back to its generic speed ladder.
    pub supported_speeds: Option<Vec<u64>>,
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
    let mut appl = connection(APPL_DB).ok();
    let mut state = connection(STATE_DB).ok();
    let counters = port_counters();
    let mut out = Vec::with_capacity(port_keys.len());
    for key in &port_keys {
        let Some(name) = key_suffix(key, "PORT|") else { continue };
        let cfg_row = hgetall_on(&mut cfg, key);
        let appl_row = state_row(&mut appl, &format!("PORT_TABLE:{name}"));
        let state_row = state_row(&mut state, &format!("PORT_TABLE|{name}"));
        let rows = vlan_rows.get(name).map(Vec::as_slice).unwrap_or(&[]);
        out.push(port_from(name, &cfg_row, &appl_row, &state_row, counters.get(name), rows));
    }
    out.sort_by(|a, b| natural_cmp(&a.name, &b.name));
    Ok(out)
}

/// Assemble one port from its CONFIG_DB row, APPL_DB row, STATE_DB row,
/// counters hash (None = no COUNTERS entry), and VLAN membership rows. Pure.
pub fn port_from(
    name: &str,
    cfg: &HashMap<String, String>,
    appl: &HashMap<String, String>,
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
        oper_status: oper_status_of(appl, state),
        speed_mbps: parse_num(field(appl, "speed"))
            .or_else(|| parse_num(field(state, "speed")))
            .or_else(|| parse_num(field(cfg, "speed"))),
        supported_speeds: parse_supported_speeds(field(state, "supported_speeds")),
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
    let mut appl = connection(APPL_DB).ok();
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
                    oper_status: member_oper(&mut appl, &mut state, &port),
                    name: port,
                    selected,
                }
            })
            .collect();
        out.push(PortChannel {
            name: name.to_string(),
            protocol: if is_static { "static" } else { "lacp" },
            admin_status: field(&row, "admin_status").unwrap_or("down").to_string(),
            oper_status: oper_status_of(
                &state_row(&mut appl, &format!("LAG_TABLE:{name}")),
                &state_row(&mut state, &format!("LAG_TABLE|{name}")),
            ),
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

/// STATE_DB's `supported_speeds` — SONiC publishes a comma-separated Mbps
/// string (e.g. "10000,25000,40000,100000"). Sorted and deduplicated;
/// malformed (and zero) entries are skipped. None when the field is absent or
/// nothing usable remains — the contract emits null, never [], so the console
/// can fall back to its generic speed ladder.
pub fn parse_supported_speeds(v: Option<&str>) -> Option<Vec<u64>> {
    let mut speeds: Vec<u64> = v?
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .filter(|&n| n > 0)
        .collect();
    if speeds.is_empty() {
        return None;
    }
    speeds.sort_unstable();
    speeds.dedup();
    Some(speeds)
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

/// Oper status from an APPL_DB row first (the authoritative source — what
/// `show interfaces status` reads), then the STATE_DB row, then "unknown".
/// Pure.
pub fn oper_status_of(appl: &HashMap<String, String>, state: &HashMap<String, String>) -> String {
    field(appl, "oper_status")
        .or_else(|| field(state, "oper_status"))
        .unwrap_or("unknown")
        .to_string()
}

/// Oper status for a member name: PORT_TABLE for ports, LAG_TABLE for
/// PortChannels (member names can be either). APPL_DB uses `:` key
/// separators, STATE_DB `|`.
fn member_oper(
    appl: &mut Option<redis::Connection>,
    state: &mut Option<redis::Connection>,
    name: &str,
) -> String {
    let table = if name.starts_with("PortChannel") { "LAG_TABLE" } else { "PORT_TABLE" };
    oper_status_of(
        &state_row(appl, &format!("{table}:{name}")),
        &state_row(state, &format!("{table}|{name}")),
    )
}

// ── write operations ────────────────────────────────────────────────────────

/// How a switching write fails. The management API maps these onto the HTTP
/// statuses the console expects: invalid payloads → 400, unknown resources →
/// 404, well-formed values the hardware can't take → 422, and an
/// unreachable/failed redis → the existing 500 shape.
#[derive(Debug)]
pub enum WriteError {
    BadRequest(String),
    NotFound(String),
    Unprocessable(String),
    Redis(anyhow::Error),
}

impl From<anyhow::Error> for WriteError {
    fn from(e: anyhow::Error) -> Self {
        WriteError::Redis(e)
    }
}

type WriteResult = std::result::Result<(), WriteError>;

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

/// Parse a JSON request body; the message is safe to surface in a 400.
pub fn parse_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> std::result::Result<T, String> {
    serde_json::from_slice(body).map_err(|e| format!("invalid body: {e}"))
}

/// Deserialize a present field as Some(inner) so a handler can distinguish
/// omitted (None — leave untouched) from null (Some(None) — clear).
fn present<'de, T, D>(d: D) -> std::result::Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdminStatus {
    Up,
    Down,
}

impl AdminStatus {
    fn as_str(self) -> &'static str {
        match self {
            AdminStatus::Up => "up",
            AdminStatus::Down => "down",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VlanModeInput {
    Access,
    Trunk,
    Routed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LagProtocol {
    Lacp,
    Static,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tagging {
    Tagged,
    Untagged,
}

impl Tagging {
    fn as_str(self) -> &'static str {
        match self {
            Tagging::Tagged => "tagged",
            Tagging::Untagged => "untagged",
        }
    }
}

/// `PUT /api/switching/ports/{name}` body — a patch: omitted fields stay
/// untouched, explicit nulls clear the CONFIG_DB field.
#[derive(Debug, Default, PartialEq, Deserialize)]
pub struct PortPatch {
    #[serde(default, deserialize_with = "present")]
    pub description: Option<Option<String>>,
    pub admin_status: Option<AdminStatus>,
    #[serde(default, deserialize_with = "present")]
    pub mtu: Option<Option<u64>>,
    #[serde(default, deserialize_with = "present")]
    pub speed_mbps: Option<Option<u64>>,
    #[serde(default, deserialize_with = "present")]
    pub fec: Option<Option<String>>,
    pub vlan_mode: Option<VlanModeInput>,
    #[serde(default, deserialize_with = "present")]
    pub untagged_vlan: Option<Option<u32>>,
    pub tagged_vlans: Option<Vec<u32>>,
}

/// One member entry in a VLAN payload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VlanMemberInput {
    pub name: String,
    pub tagging: Tagging,
}

/// `POST/PUT /api/switching/vlans` body (create carries `vlan_id` too). The
/// lists are full desired sets; absent/null description means no description.
#[derive(Debug, Default, Deserialize)]
pub struct VlanInput {
    pub description: Option<String>,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    #[serde(default)]
    pub dhcp_helpers: Vec<String>,
    #[serde(default)]
    pub members: Vec<VlanMemberInput>,
}

#[derive(Debug, Deserialize)]
pub struct VlanCreate {
    pub vlan_id: u32,
    #[serde(flatten)]
    pub input: VlanInput,
}

/// `POST/PUT /api/switching/port-channels` body (create carries `name` too).
/// Unlike PortPatch this is a full desired object: absent/null mtu and
/// min_links mean "not configured" and clear the field.
#[derive(Debug, Deserialize)]
pub struct PortChannelInput {
    pub protocol: LagProtocol,
    pub admin_status: AdminStatus,
    pub mtu: Option<u64>,
    pub min_links: Option<u64>,
    #[serde(default)]
    pub fallback: bool,
    #[serde(default)]
    pub fast_rate: bool,
    #[serde(default)]
    pub members: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PortChannelCreate {
    pub name: String,
    #[serde(flatten)]
    pub input: PortChannelInput,
}

// ── pure validation / diff helpers ──────────────────────────────────────────

/// The desired VLAN_MEMBER rows (vlan id → tagging_mode) for a port under a
/// patch's vlan_mode triple. Errors on access without an untagged VLAN and on
/// out-of-range VLAN ids.
pub fn desired_vlan_rows(
    mode: VlanModeInput,
    untagged: Option<u32>,
    tagged: &[u32],
) -> std::result::Result<HashMap<u32, &'static str>, String> {
    let mut rows = HashMap::new();
    match mode {
        VlanModeInput::Routed => {}
        VlanModeInput::Access => {
            let id = untagged.ok_or("access mode requires untagged_vlan")?;
            rows.insert(check_vlan_id(id)?, "untagged");
        }
        VlanModeInput::Trunk => {
            for &id in tagged {
                rows.insert(check_vlan_id(id)?, "tagged");
            }
            // The native VLAN row wins if it also appears in tagged_vlans.
            if let Some(id) = untagged {
                rows.insert(check_vlan_id(id)?, "untagged");
            }
        }
    }
    Ok(rows)
}

/// Set-converge diff: (keys to delete, key/value pairs to write). Rows whose
/// value already matches are left untouched; output is sorted so writes apply
/// deterministically.
pub fn diff_rows(
    current: &HashMap<String, String>,
    desired: &HashMap<String, String>,
) -> (Vec<String>, Vec<(String, String)>) {
    let mut dels: Vec<String> =
        current.keys().filter(|k| !desired.contains_key(*k)).cloned().collect();
    let mut sets: Vec<(String, String)> = desired
        .iter()
        .filter(|(k, v)| current.get(*k) != Some(*v))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    dels.sort();
    sets.sort();
    (dels, sets)
}

/// "PortChannel" + 1–4 digits — the LAG name shape SONiC's own CLI accepts.
pub fn valid_port_channel_name(name: &str) -> bool {
    name.strip_prefix("PortChannel")
        .map(|d| !d.is_empty() && d.len() <= 4 && d.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false)
}

/// 1..=4094, echoed back for insertion; the error is a 400 message.
pub fn check_vlan_id(id: u32) -> std::result::Result<u32, String> {
    if (1..=4094).contains(&id) {
        Ok(id)
    } else {
        Err(format!("invalid VLAN id {id} (must be 1-4094)"))
    }
}

/// Light CIDR sanity: enough shape to form a valid VLAN_INTERFACE key —
/// address/prefix with no whitespace and no `|` (which would corrupt the key).
pub fn check_cidrs(addrs: &[String]) -> std::result::Result<(), String> {
    for a in addrs {
        let ok = a.split_once('/').is_some_and(|(ip, len)| {
            !ip.is_empty() && !len.is_empty() && len.bytes().all(|b| b.is_ascii_digit())
        }) && !a.contains('|')
            && !a.contains(char::is_whitespace);
        if !ok {
            return Err(format!("invalid CIDR address {a:?}"));
        }
    }
    Ok(())
}

/// VLAN member list → name → tagging_mode map; duplicate names are a 400
/// (two rows for one member can't both exist).
pub fn vlan_member_map(
    members: &[VlanMemberInput],
) -> std::result::Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    for m in members {
        if map.insert(m.name.clone(), m.tagging.as_str().to_string()).is_some() {
            return Err(format!("duplicate VLAN member {}", m.name));
        }
    }
    Ok(map)
}

/// Port-channel member list, deduped-or-rejected.
pub fn unique_members(members: &[String]) -> std::result::Result<Vec<String>, String> {
    let mut seen = Vec::with_capacity(members.len());
    for m in members {
        if seen.contains(m) {
            return Err(format!("duplicate member {m}"));
        }
        seen.push(m.clone());
    }
    Ok(seen)
}

fn check_mtu(v: u64) -> std::result::Result<(), String> {
    if (68..=9216).contains(&v) {
        Ok(())
    } else {
        Err(format!("invalid mtu {v} (must be 68-9216)"))
    }
}

fn check_speed(v: u64) -> std::result::Result<(), String> {
    if v > 0 {
        Ok(())
    } else {
        Err("speed_mbps must be positive".to_string())
    }
}

/// A speed the platform says the port can't run is a 422. None (STATE_DB
/// didn't publish supported_speeds) accepts anything — best-effort, as
/// before the field existed.
pub fn check_supported_speed(
    speed: u64,
    supported: Option<&[u64]>,
) -> std::result::Result<(), String> {
    match supported {
        Some(list) if !list.contains(&speed) => Err(format!(
            "unsupported speed {speed} (supported: {})",
            list.iter().map(u64::to_string).collect::<Vec<_>>().join(", ")
        )),
        _ => Ok(()),
    }
}

// ── redis write primitives ──────────────────────────────────────────────────

fn hset(conn: &mut redis::Connection, key: &str, f: &str, v: &str) -> Result<()> {
    redis::cmd("HSET")
        .arg(key)
        .arg(f)
        .arg(v)
        .query(conn)
        .with_context(|| format!("HSET {key} {f}"))
}

fn hdel(conn: &mut redis::Connection, key: &str, f: &str) -> Result<()> {
    redis::cmd("HDEL")
        .arg(key)
        .arg(f)
        .query(conn)
        .with_context(|| format!("HDEL {key} {f}"))
}

fn del(conn: &mut redis::Connection, key: &str) -> Result<()> {
    redis::cmd("DEL").arg(key).query(conn).with_context(|| format!("DEL {key}"))
}

fn key_exists(conn: &mut redis::Connection, key: &str) -> Result<bool> {
    let n: i64 = redis::cmd("EXISTS")
        .arg(key)
        .query(conn)
        .with_context(|| format!("EXISTS {key}"))?;
    Ok(n > 0)
}

/// Apply one tri-state patch field: Some(Some) → HSET, Some(None) → HDEL,
/// None → untouched.
fn apply_patch_field(
    conn: &mut redis::Connection,
    key: &str,
    f: &str,
    v: &Option<Option<String>>,
) -> Result<()> {
    match v {
        Some(Some(v)) => hset(conn, key, f, v),
        Some(None) => hdel(conn, key, f),
        None => Ok(()),
    }
}

// ── operations ──────────────────────────────────────────────────────────────

/// `PUT /api/switching/ports/{name}` — patch scalar PORT fields and, when
/// vlan_mode is present, converge the port's VLAN_MEMBER rows.
pub fn update_port(name: &str, patch: &PortPatch) -> WriteResult {
    // Everything checkable without redis is checked first, so a bad payload
    // is a 400 even while redis is down.
    if let Some(Some(v)) = patch.mtu {
        check_mtu(v).map_err(bad)?;
    }
    if let Some(Some(v)) = patch.speed_mbps {
        check_speed(v).map_err(bad)?;
    }
    let desired = match patch.vlan_mode {
        Some(mode) => Some(
            desired_vlan_rows(
                mode,
                patch.untagged_vlan.flatten(),
                patch.tagged_vlans.as_deref().unwrap_or(&[]),
            )
            .map_err(bad)?,
        ),
        None => None,
    };

    let mut cfg = connection(CONFIG_DB)?;
    let port_key = format!("PORT|{name}");
    if !key_exists(&mut cfg, &port_key)? {
        return Err(WriteError::NotFound(format!("no such port {name}")));
    }
    if let Some(Some(v)) = patch.speed_mbps {
        // STATE_DB unreachable or silent on supported_speeds → accept the
        // value as before (best-effort); a published list is enforced.
        let mut state = connection(STATE_DB).ok();
        let row = state_row(&mut state, &format!("PORT_TABLE|{name}"));
        let supported = parse_supported_speeds(field(&row, "supported_speeds"));
        check_supported_speed(v, supported.as_deref()).map_err(WriteError::Unprocessable)?;
    }
    if let Some(rows) = &desired {
        for id in rows.keys() {
            if !key_exists(&mut cfg, &format!("VLAN|Vlan{id}"))? {
                return Err(bad(format!("VLAN {id} does not exist")));
            }
        }
    }

    apply_patch_field(&mut cfg, &port_key, "description", &patch.description)?;
    if let Some(v) = patch.admin_status {
        hset(&mut cfg, &port_key, "admin_status", v.as_str())?;
    }
    match patch.mtu {
        Some(Some(v)) => hset(&mut cfg, &port_key, "mtu", &v.to_string())?,
        Some(None) => hdel(&mut cfg, &port_key, "mtu")?,
        None => {}
    }
    match patch.speed_mbps {
        Some(Some(v)) => hset(&mut cfg, &port_key, "speed", &v.to_string())?,
        Some(None) => hdel(&mut cfg, &port_key, "speed")?,
        None => {}
    }
    apply_patch_field(&mut cfg, &port_key, "fec", &patch.fec)?;

    if let Some(rows) = desired {
        // Current membership, keyed by vlan id (as a string for diff_rows).
        let mut current = HashMap::new();
        for key in scan_keys(&mut cfg, "VLAN_MEMBER|*")? {
            let Some((vlan, member)) = member_parts(&key, "VLAN_MEMBER|") else { continue };
            if member != name {
                continue;
            }
            let Some(id) = vlan_id_from_name(vlan) else { continue };
            let mode = field(&hgetall_on(&mut cfg, &key), "tagging_mode")
                .unwrap_or("untagged")
                .to_string();
            current.insert(id.to_string(), mode);
        }
        let desired: HashMap<String, String> =
            rows.into_iter().map(|(id, m)| (id.to_string(), m.to_string())).collect();
        let (dels, sets) = diff_rows(&current, &desired);
        for id in dels {
            del(&mut cfg, &format!("VLAN_MEMBER|Vlan{id}|{name}"))?;
        }
        for (id, mode) in sets {
            hset(&mut cfg, &format!("VLAN_MEMBER|Vlan{id}|{name}"), "tagging_mode", &mode)?;
        }
    }
    Ok(())
}

/// Each VLAN member must be an existing port or port channel — a payload
/// reference, so a miss is a 400 (404 is reserved for the path resource).
fn check_members_exist(
    cfg: &mut redis::Connection,
    members: &HashMap<String, String>,
) -> WriteResult {
    for name in members.keys() {
        if !key_exists(cfg, &format!("PORT|{name}"))?
            && !key_exists(cfg, &format!("PORTCHANNEL|{name}"))?
        {
            return Err(bad(format!("no such interface {name}")));
        }
    }
    Ok(())
}

/// `POST /api/switching/vlans`.
pub fn create_vlan(vlan_id: u32, input: &VlanInput) -> WriteResult {
    check_vlan_id(vlan_id).map_err(bad)?;
    let members = vlan_member_map(&input.members).map_err(bad)?;
    check_cidrs(&input.ip_addresses).map_err(bad)?;

    let mut cfg = connection(CONFIG_DB)?;
    let key = format!("VLAN|Vlan{vlan_id}");
    if key_exists(&mut cfg, &key)? {
        return Err(bad(format!("Vlan{vlan_id} already exists")));
    }
    check_members_exist(&mut cfg, &members)?;

    hset(&mut cfg, &key, "vlanid", &vlan_id.to_string())?;
    if let Some(d) = &input.description {
        hset(&mut cfg, &key, "description", d)?;
    }
    if !input.dhcp_helpers.is_empty() {
        hset(&mut cfg, &key, "dhcp_servers@", &input.dhcp_helpers.join(","))?;
    }
    for (name, tagging) in &members {
        hset(&mut cfg, &format!("VLAN_MEMBER|Vlan{vlan_id}|{name}"), "tagging_mode", tagging)?;
    }
    if !input.ip_addresses.is_empty() {
        // SONiC's intfmgrd only picks up the per-address child keys when the
        // two-part parent row exists; NULL:NULL is the CLI's keyless-row idiom.
        hset(&mut cfg, &format!("VLAN_INTERFACE|Vlan{vlan_id}"), "NULL", "NULL")?;
        for cidr in &input.ip_addresses {
            hset(&mut cfg, &format!("VLAN_INTERFACE|Vlan{vlan_id}|{cidr}"), "NULL", "NULL")?;
        }
    }
    Ok(())
}

/// `PUT /api/switching/vlans/{vlan_id}` — converge description, members,
/// addresses, and DHCP helpers to the given sets.
pub fn update_vlan(vlan_id: u32, input: &VlanInput) -> WriteResult {
    let members = vlan_member_map(&input.members).map_err(bad)?;
    check_cidrs(&input.ip_addresses).map_err(bad)?;

    let mut cfg = connection(CONFIG_DB)?;
    let vlan = format!("Vlan{vlan_id}");
    let key = format!("VLAN|{vlan}");
    if !key_exists(&mut cfg, &key)? {
        return Err(WriteError::NotFound(format!("no such VLAN {vlan}")));
    }
    check_members_exist(&mut cfg, &members)?;

    match &input.description {
        Some(d) => hset(&mut cfg, &key, "description", d)?,
        None => hdel(&mut cfg, &key, "description")?,
    }
    if input.dhcp_helpers.is_empty() {
        // Drop the plain-name variant too so the reader can't fall back to a
        // stale list written by other tooling.
        hdel(&mut cfg, &key, "dhcp_servers@")?;
        hdel(&mut cfg, &key, "dhcp_servers")?;
    } else {
        hset(&mut cfg, &key, "dhcp_servers@", &input.dhcp_helpers.join(","))?;
    }

    let mut current = HashMap::new();
    for k in scan_keys(&mut cfg, &format!("VLAN_MEMBER|{vlan}|*"))? {
        if let Some((_, member)) = member_parts(&k, "VLAN_MEMBER|") {
            let mode = field(&hgetall_on(&mut cfg, &k), "tagging_mode")
                .unwrap_or("untagged")
                .to_string();
            current.insert(member.to_string(), mode);
        }
    }
    let (dels, sets) = diff_rows(&current, &members);
    for m in dels {
        del(&mut cfg, &format!("VLAN_MEMBER|{vlan}|{m}"))?;
    }
    for (m, t) in sets {
        hset(&mut cfg, &format!("VLAN_MEMBER|{vlan}|{m}"), "tagging_mode", &t)?;
    }

    let mut cur_ips = HashMap::new();
    for k in scan_keys(&mut cfg, &format!("VLAN_INTERFACE|{vlan}|*"))? {
        if let Some((_, cidr)) = member_parts(&k, "VLAN_INTERFACE|") {
            cur_ips.insert(cidr.to_string(), String::new());
        }
    }
    let want: HashMap<String, String> =
        input.ip_addresses.iter().map(|c| (c.clone(), String::new())).collect();
    let (dels, sets) = diff_rows(&cur_ips, &want);
    for c in dels {
        del(&mut cfg, &format!("VLAN_INTERFACE|{vlan}|{c}"))?;
    }
    if want.is_empty() {
        del(&mut cfg, &format!("VLAN_INTERFACE|{vlan}"))?;
    } else {
        hset(&mut cfg, &format!("VLAN_INTERFACE|{vlan}"), "NULL", "NULL")?;
        for (c, _) in sets {
            hset(&mut cfg, &format!("VLAN_INTERFACE|{vlan}|{c}"), "NULL", "NULL")?;
        }
    }
    Ok(())
}

/// `DELETE /api/switching/vlans/{vlan_id}` — the VLAN key plus every
/// VLAN_MEMBER and VLAN_INTERFACE row that hangs off it.
pub fn delete_vlan(vlan_id: u32) -> WriteResult {
    let mut cfg = connection(CONFIG_DB)?;
    let vlan = format!("Vlan{vlan_id}");
    if !key_exists(&mut cfg, &format!("VLAN|{vlan}"))? {
        return Err(WriteError::NotFound(format!("no such VLAN {vlan}")));
    }
    for k in scan_keys(&mut cfg, &format!("VLAN_MEMBER|{vlan}|*"))? {
        del(&mut cfg, &k)?;
    }
    for k in scan_keys(&mut cfg, &format!("VLAN_INTERFACE|{vlan}|*"))? {
        del(&mut cfg, &k)?;
    }
    del(&mut cfg, &format!("VLAN_INTERFACE|{vlan}"))?;
    del(&mut cfg, &format!("VLAN|{vlan}"))?;
    Ok(())
}

/// The PORTCHANNEL scalar fields shared by create and update. protocol maps
/// to the `static` field ("true" for static, cleared for LACP); absent
/// mtu/min_links clear theirs (the input is a full desired object).
fn write_port_channel_fields(
    cfg: &mut redis::Connection,
    key: &str,
    input: &PortChannelInput,
) -> Result<()> {
    hset(cfg, key, "admin_status", input.admin_status.as_str())?;
    match input.protocol {
        LagProtocol::Static => hset(cfg, key, "static", "true")?,
        LagProtocol::Lacp => hdel(cfg, key, "static")?,
    }
    match input.mtu {
        Some(v) => hset(cfg, key, "mtu", &v.to_string())?,
        None => hdel(cfg, key, "mtu")?,
    }
    match input.min_links {
        Some(v) => hset(cfg, key, "min_links", &v.to_string())?,
        None => hdel(cfg, key, "min_links")?,
    }
    hset(cfg, key, "fallback", if input.fallback { "true" } else { "false" })?;
    hset(cfg, key, "fast_rate", if input.fast_rate { "true" } else { "false" })
}

/// Payload-level port-channel validation shared by create and update.
fn check_port_channel_input(input: &PortChannelInput) -> std::result::Result<Vec<String>, String> {
    if let Some(v) = input.mtu {
        check_mtu(v)?;
    }
    if input.min_links == Some(0) {
        return Err("min_links must be positive".to_string());
    }
    unique_members(&input.members)
}

/// Port-channel members must be existing physical ports.
fn check_ports_exist(cfg: &mut redis::Connection, members: &[String]) -> WriteResult {
    for m in members {
        if !key_exists(cfg, &format!("PORT|{m}"))? {
            return Err(bad(format!("no such port {m}")));
        }
    }
    Ok(())
}

/// `POST /api/switching/port-channels`.
pub fn create_port_channel(name: &str, input: &PortChannelInput) -> WriteResult {
    if !valid_port_channel_name(name) {
        return Err(bad(format!(
            "invalid port channel name {name:?} (expected PortChannel<1-4 digits>)"
        )));
    }
    let members = check_port_channel_input(input).map_err(bad)?;

    let mut cfg = connection(CONFIG_DB)?;
    let key = format!("PORTCHANNEL|{name}");
    if key_exists(&mut cfg, &key)? {
        return Err(bad(format!("{name} already exists")));
    }
    check_ports_exist(&mut cfg, &members)?;

    write_port_channel_fields(&mut cfg, &key, input)?;
    for m in &members {
        hset(&mut cfg, &format!("PORTCHANNEL_MEMBER|{name}|{m}"), "NULL", "NULL")?;
    }
    Ok(())
}

/// `PUT /api/switching/port-channels/{name}` — converge fields + member set.
pub fn update_port_channel(name: &str, input: &PortChannelInput) -> WriteResult {
    let members = check_port_channel_input(input).map_err(bad)?;

    let mut cfg = connection(CONFIG_DB)?;
    let key = format!("PORTCHANNEL|{name}");
    if !key_exists(&mut cfg, &key)? {
        return Err(WriteError::NotFound(format!("no such port channel {name}")));
    }
    check_ports_exist(&mut cfg, &members)?;

    write_port_channel_fields(&mut cfg, &key, input)?;
    let mut current = HashMap::new();
    for k in scan_keys(&mut cfg, &format!("PORTCHANNEL_MEMBER|{name}|*"))? {
        if let Some((_, port)) = member_parts(&k, "PORTCHANNEL_MEMBER|") {
            current.insert(port.to_string(), String::new());
        }
    }
    let want: HashMap<String, String> =
        members.iter().map(|m| (m.clone(), String::new())).collect();
    let (dels, sets) = diff_rows(&current, &want);
    for m in dels {
        del(&mut cfg, &format!("PORTCHANNEL_MEMBER|{name}|{m}"))?;
    }
    for (m, _) in sets {
        hset(&mut cfg, &format!("PORTCHANNEL_MEMBER|{name}|{m}"), "NULL", "NULL")?;
    }
    Ok(())
}

/// `DELETE /api/switching/port-channels/{name}`.
pub fn delete_port_channel(name: &str) -> WriteResult {
    let mut cfg = connection(CONFIG_DB)?;
    let key = format!("PORTCHANNEL|{name}");
    if !key_exists(&mut cfg, &key)? {
        return Err(WriteError::NotFound(format!("no such port channel {name}")));
    }
    for k in scan_keys(&mut cfg, &format!("PORTCHANNEL_MEMBER|{name}|*"))? {
        del(&mut cfg, &k)?;
    }
    del(&mut cfg, &key)?;
    Ok(())
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
    fn supported_speeds_parse_sorted_deduped_and_defensively() {
        assert_eq!(
            parse_supported_speeds(Some("100000,40000,10000,25000")),
            Some(vec![10_000, 25_000, 40_000, 100_000])
        );
        // Duplicates collapse; whitespace and malformed entries are skipped.
        assert_eq!(
            parse_supported_speeds(Some(" 25000 ,10000,25000,fast,0")),
            Some(vec![10_000, 25_000])
        );
        // Absent or nothing usable → None (the contract's null, never []).
        assert_eq!(parse_supported_speeds(None), None);
        assert_eq!(parse_supported_speeds(Some("")), None);
        assert_eq!(parse_supported_speeds(Some("N/A,,")), None);
    }

    #[test]
    fn supported_speed_check_enforces_published_lists_only() {
        assert!(check_supported_speed(25_000, Some(&[10_000, 25_000])).is_ok());
        let err = check_supported_speed(40_000, Some(&[10_000, 25_000])).unwrap_err();
        assert!(err.contains("unsupported speed 40000"), "{err}");
        assert!(err.contains("10000, 25000"), "{err}");
        // No published list → best-effort, accept anything.
        assert!(check_supported_speed(40_000, None).is_ok());
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
            &h(&[
                ("oper_status", "down"),
                ("speed", "50000"),
                ("supported_speeds", "100000,40000,10000,25000"),
            ]),
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
        // APPL_DB oper/speed win over STATE_DB and CONFIG_DB.
        assert_eq!(p.oper_status, "up");
        assert_eq!(p.speed_mbps, Some(100_000));
        // supported_speeds comes from STATE_DB, sorted.
        assert_eq!(p.supported_speeds, Some(vec![10_000, 25_000, 40_000, 100_000]));
        assert_eq!(p.mtu, Some(9100));
        assert_eq!(p.vlan_mode, Some("trunk"));
        assert_eq!(p.untagged_vlan, Some(10));
        assert_eq!(p.tagged_vlans, vec![20]);
        assert_eq!(p.rx_err, Some(3));
        assert_eq!(p.tx_drops, Some(1));
    }

    #[test]
    fn port_degrades_field_by_field() {
        let p =
            port_from("Ethernet4", &HashMap::new(), &HashMap::new(), &HashMap::new(), None, &[]);
        assert_eq!(p.admin_status, "down"); // SONiC default
        assert_eq!(p.oper_status, "unknown");
        assert_eq!(p.speed_mbps, None);
        assert_eq!(p.supported_speeds, None);
        assert_eq!(p.alias, None);
        assert_eq!(p.mtu, None);
        assert_eq!(p.vlan_mode, Some("routed"));
        // No counters entry → null, not zero.
        assert_eq!(p.rx_err, None);
        assert_eq!(p.tx_err, None);
        // CONFIG_DB speed used when APPL_DB/STATE_DB have none; garbage → null.
        let p = port_from(
            "Ethernet8",
            &h(&[("speed", "25000"), ("mtu", "jumbo")]),
            &HashMap::new(),
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
    fn oper_status_prefers_appl_db_then_state_db() {
        // APPL_DB is the authority — the STATE_DB row (transceiver/init
        // state on most platforms) only breaks an APPL_DB miss.
        assert_eq!(oper_status_of(&h(&[("oper_status", "up")]), &HashMap::new()), "up");
        assert_eq!(
            oper_status_of(&h(&[("oper_status", "down")]), &h(&[("oper_status", "up")])),
            "down"
        );
        assert_eq!(oper_status_of(&HashMap::new(), &h(&[("oper_status", "up")])), "up");
        assert_eq!(oper_status_of(&HashMap::new(), &HashMap::new()), "unknown");
        // STATE_DB speed still wins over CONFIG_DB when APPL_DB has none.
        let p = port_from(
            "Ethernet0",
            &h(&[("speed", "40000")]),
            &HashMap::new(),
            &h(&[("speed", "100000")]),
            None,
            &[],
        );
        assert_eq!(p.speed_mbps, Some(100_000));
    }

    #[test]
    fn port_serializes_to_the_contract_shape() {
        let v = serde_json::to_value(port_from(
            "Ethernet4",
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            None,
            &[],
        ))
        .unwrap();
        assert_eq!(v["name"], "Ethernet4");
        assert!(v["alias"].is_null());
        assert!(v["speed_mbps"].is_null());
        // Unpublished supported_speeds must serialize as null, never [].
        assert!(v["supported_speeds"].is_null());
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

    // ── write helpers ───────────────────────────────────────────────────────

    #[test]
    fn port_patch_distinguishes_omitted_from_null() {
        let p: PortPatch = parse_json(b"{}").unwrap();
        assert_eq!(p, PortPatch::default());
        let p: PortPatch =
            parse_json(br#"{"mtu": null, "speed_mbps": 100000, "description": null}"#).unwrap();
        assert_eq!(p.mtu, Some(None)); // null → clear
        assert_eq!(p.speed_mbps, Some(Some(100_000)));
        assert_eq!(p.description, Some(None));
        assert_eq!(p.fec, None); // omitted → untouched
        let p: PortPatch =
            parse_json(br#"{"admin_status": "down", "vlan_mode": "trunk", "tagged_vlans": [10]}"#)
                .unwrap();
        assert_eq!(p.admin_status, Some(AdminStatus::Down));
        assert_eq!(p.vlan_mode, Some(VlanModeInput::Trunk));
        assert_eq!(p.tagged_vlans, Some(vec![10]));
    }

    #[test]
    fn port_patch_rejects_bad_enums_and_bodies() {
        assert!(parse_json::<PortPatch>(br#"{"admin_status": "sideways"}"#).is_err());
        assert!(parse_json::<PortPatch>(br#"{"vlan_mode": "hybrid"}"#).is_err());
        assert!(parse_json::<PortPatch>(b"not json").is_err());
        assert!(parse_json::<PortPatch>(br#"{"mtu": -1}"#).is_err());
    }

    #[test]
    fn vlan_create_parses_with_flattened_input() {
        let c: VlanCreate = parse_json(
            br#"{"vlan_id": 20, "description": "users",
                 "ip_addresses": ["10.0.20.1/24"], "dhcp_helpers": ["10.0.0.5"],
                 "members": [{"name": "Ethernet0", "tagging": "untagged"}]}"#,
        )
        .unwrap();
        assert_eq!(c.vlan_id, 20);
        assert_eq!(c.input.description.as_deref(), Some("users"));
        assert_eq!(c.input.ip_addresses, vec!["10.0.20.1/24"]);
        assert_eq!(c.input.members[0].tagging, Tagging::Untagged);
        // Lists default to empty when omitted.
        let c: VlanCreate = parse_json(br#"{"vlan_id": 30}"#).unwrap();
        assert!(c.input.members.is_empty() && c.input.ip_addresses.is_empty());
    }

    #[test]
    fn port_channel_create_parses_with_flattened_input() {
        let c: PortChannelCreate = parse_json(
            br#"{"name": "PortChannel0001", "protocol": "lacp", "admin_status": "up",
                 "mtu": 9100, "min_links": 2, "fallback": true, "fast_rate": false,
                 "members": ["Ethernet0", "Ethernet4"]}"#,
        )
        .unwrap();
        assert_eq!(c.name, "PortChannel0001");
        assert_eq!(c.input.protocol, LagProtocol::Lacp);
        assert_eq!(c.input.mtu, Some(9100));
        assert!(c.input.fallback && !c.input.fast_rate);
        assert_eq!(c.input.members, vec!["Ethernet0", "Ethernet4"]);
        assert!(parse_json::<PortChannelCreate>(br#"{"name": "Po1", "protocol": "pagp"}"#).is_err());
    }

    #[test]
    fn desired_vlan_rows_cover_the_three_modes() {
        assert!(desired_vlan_rows(VlanModeInput::Routed, Some(10), &[20]).unwrap().is_empty());
        let access = desired_vlan_rows(VlanModeInput::Access, Some(10), &[]).unwrap();
        assert_eq!(access.get(&10), Some(&"untagged"));
        assert_eq!(access.len(), 1);
        let trunk = desired_vlan_rows(VlanModeInput::Trunk, Some(10), &[20, 30]).unwrap();
        assert_eq!(trunk.get(&10), Some(&"untagged"));
        assert_eq!(trunk.get(&20), Some(&"tagged"));
        assert_eq!(trunk.get(&30), Some(&"tagged"));
        // Native VLAN wins when listed in tagged_vlans too.
        let trunk = desired_vlan_rows(VlanModeInput::Trunk, Some(10), &[10]).unwrap();
        assert_eq!(trunk.get(&10), Some(&"untagged"));
        // Trunk without a native VLAN is fine.
        assert_eq!(desired_vlan_rows(VlanModeInput::Trunk, None, &[20]).unwrap().len(), 1);
    }

    #[test]
    fn desired_vlan_rows_reject_invalid_input() {
        assert!(desired_vlan_rows(VlanModeInput::Access, None, &[]).is_err());
        assert!(desired_vlan_rows(VlanModeInput::Access, Some(0), &[]).is_err());
        assert!(desired_vlan_rows(VlanModeInput::Trunk, None, &[4095]).is_err());
    }

    #[test]
    fn diff_rows_converges_without_touching_unchanged() {
        let current = h(&[("10", "untagged"), ("20", "tagged"), ("30", "tagged")]);
        let desired = h(&[("10", "untagged"), ("20", "untagged"), ("40", "tagged")]);
        let (dels, sets) = diff_rows(&current, &desired);
        assert_eq!(dels, vec!["30"]); // gone from desired
        // 10 unchanged → untouched; 20 retagged and 40 new → written.
        assert_eq!(
            sets,
            vec![("20".into(), "untagged".into()), ("40".into(), "tagged".into())]
        );
        let (dels, sets) = diff_rows(&current, &current);
        assert!(dels.is_empty() && sets.is_empty());
    }

    #[test]
    fn port_channel_names_validate_sonics_shape() {
        assert!(valid_port_channel_name("PortChannel0001"));
        assert!(valid_port_channel_name("PortChannel1"));
        assert!(valid_port_channel_name("PortChannel9999"));
        assert!(!valid_port_channel_name("PortChannel"));
        assert!(!valid_port_channel_name("PortChannel10000"));
        assert!(!valid_port_channel_name("PortChannel00a1"));
        assert!(!valid_port_channel_name("Po1"));
        assert!(!valid_port_channel_name("portchannel0001"));
    }

    #[test]
    fn vlan_ids_and_cidrs_validate() {
        assert!(check_vlan_id(1).is_ok() && check_vlan_id(4094).is_ok());
        assert!(check_vlan_id(0).is_err() && check_vlan_id(4095).is_err());
        assert!(check_cidrs(&["10.0.10.1/24".into(), "fd00::1/64".into()]).is_ok());
        assert!(check_cidrs(&[]).is_ok());
        assert!(check_cidrs(&["10.0.10.1".into()]).is_err()); // no prefix
        assert!(check_cidrs(&["10.0.10.1/24 ".into()]).is_err()); // whitespace
        assert!(check_cidrs(&["10.0.10.1/x".into()]).is_err());
        assert!(check_cidrs(&["a|b/24".into()]).is_err()); // would corrupt the key
    }

    #[test]
    fn member_lists_reject_duplicates() {
        let m = |name: &str, tagging| VlanMemberInput { name: name.into(), tagging };
        let map = vlan_member_map(&[
            m("Ethernet0", Tagging::Untagged),
            m("PortChannel0001", Tagging::Tagged),
        ])
        .unwrap();
        assert_eq!(map.get("Ethernet0").map(String::as_str), Some("untagged"));
        assert_eq!(map.get("PortChannel0001").map(String::as_str), Some("tagged"));
        assert!(vlan_member_map(&[m("Ethernet0", Tagging::Untagged), m("Ethernet0", Tagging::Tagged)])
            .is_err());
        assert_eq!(
            unique_members(&["Ethernet0".into(), "Ethernet4".into()]).unwrap().len(),
            2
        );
        assert!(unique_members(&["Ethernet0".into(), "Ethernet0".into()]).is_err());
    }
}
