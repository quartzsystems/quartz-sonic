//! BGP for the console's Configure → Routing → BGP page, with two backends
//! selected by the capability probe:
//!
//! * **frrcfgd** (preferred; `frr_mgmt_framework_config=true`, which we
//!   enable at enrollment where possible): the structured CONFIG_DB tables
//!   frrcfgd consumes — `BGP_GLOBALS|<vrf>`, `BGP_GLOBALS_AF|<vrf>|<afi_safi>`
//!   (max_ebgp_paths/max_ibgp_paths), `BGP_NEIGHBOR|<vrf>|<peer>` (3-part
//!   key; peer = IP or interface) and `BGP_NEIGHBOR_AF|<vrf>|<peer>|<afi_safi>`
//!   (admin_status=true enables the AF). frrcfgd.py's field maps are the
//!   schema truth (no yang model exists).
//! * **legacy** (community without frrcfgd): flat `BGP_NEIGHBOR|<peer-ip>`
//!   rows plus DEVICE_METADATA bgp_asn, the schema bgpcfgd understands. The
//!   reduced surface (no VRFs, peer groups, BFD, multihop, per-AF control)
//!   is reported in the capability reason and enforced with clear errors.
//!
//! BGP_GLOBALS* tables are NEVER written when frrcfgd isn't running — they
//! would sit inert and lie to the next reader.
//!
//! Session state merges STATE_DB `NEIGH_STATE_TABLE|<peer>` (bgpmon) with
//! `vtysh -c "show bgp vrf all summary json"` for prefixes/uptime.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, BgpMode, Capability};
use super::store::{self, field, key_suffix, keys, row, three_parts, two_parts, Platform};
use super::switching::{parse_bool, parse_num, AdminStatus, WriteError, WriteResult};
use super::{CONFIG_DB, STATE_DB};

const LEGACY_REASON: &str = "legacy flat BGP schema (frr_mgmt_framework_config off): no VRFs, \
                             peer groups, BFD, multihop TTL, or per-AF control";
const UNAVAILABLE_REASON: &str = "BGP is not available on this image (no bgp feature/container)";

fn capability(mode: BgpMode) -> Capability {
    match mode {
        BgpMode::Frrcfgd => Capability::yes(),
        BgpMode::Legacy => Capability::yes_with_reason(LEGACY_REASON),
        BgpMode::Unavailable => Capability::no(UNAVAILABLE_REASON),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum Af {
    #[serde(rename = "ipv4_unicast")]
    Ipv4Unicast,
    #[serde(rename = "ipv6_unicast")]
    Ipv6Unicast,
    #[serde(rename = "l2vpn_evpn")]
    L2vpnEvpn,
}

impl Af {
    pub fn as_str(self) -> &'static str {
        match self {
            Af::Ipv4Unicast => "ipv4_unicast",
            Af::Ipv6Unicast => "ipv6_unicast",
            Af::L2vpnEvpn => "l2vpn_evpn",
        }
    }
}

// ── GET /api/routing/bgp ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct GlobalDoc {
    vrf: String,
    local_asn: Option<u64>,
    router_id: Option<String>,
    keepalive: Option<u64>,
    holdtime: Option<u64>,
    graceful_restart: bool,
    max_ebgp_paths: Option<u64>,
    max_ibgp_paths: Option<u64>,
}

#[derive(Debug, Serialize)]
struct NeighborDoc {
    vrf: String,
    peer: String,
    remote_asn: Option<u64>,
    name: Option<String>,
    peer_group: Option<String>,
    local_addr: Option<String>,
    keepalive: Option<u64>,
    holdtime: Option<u64>,
    ebgp_multihop_ttl: Option<u64>,
    bfd: bool,
    admin_status: String,
    address_families: Vec<&'static str>,
    session_state: Option<String>,
    prefixes_received: Option<u64>,
    uptime_secs: Option<u64>,
}

/// One peer's live-session digest out of the vtysh summary.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionInfo {
    pub state: Option<String>,
    pub prefixes_received: Option<u64>,
    pub uptime_secs: Option<u64>,
}

/// Parse `show bgp vrf all summary json`: vrf → AF section → "peers". Pure
/// and tolerant — anything unexpected just yields no session info.
pub fn parse_bgp_summary(text: &str) -> HashMap<(String, String), SessionInfo> {
    let mut out = HashMap::new();
    let Ok(root) = serde_json::from_str::<serde_json::Value>(text) else {
        return out;
    };
    let Some(vrfs) = root.as_object() else { return out };
    for (vrf, sections) in vrfs {
        let Some(sections) = sections.as_object() else { continue };
        for section in sections.values() {
            let Some(peers) = section.get("peers").and_then(|p| p.as_object()) else {
                continue;
            };
            for (peer, info) in peers {
                let entry: &mut SessionInfo =
                    out.entry((vrf.clone(), peer.clone())).or_default();
                if let Some(state) = info.get("state").and_then(|v| v.as_str()) {
                    entry.state = Some(state.to_string());
                }
                // pfxRcd across AFs: keep the sum so a dual-AF peer reports
                // everything it sent us.
                if let Some(n) = info.get("pfxRcd").and_then(|v| v.as_u64()) {
                    *entry.prefixes_received.get_or_insert(0) += n;
                }
                if let Some(ms) = info.get("peerUptimeMsec").and_then(|v| v.as_u64()) {
                    entry.uptime_secs = Some(ms / 1000);
                }
            }
        }
    }
    out
}

fn sessions(plat: &mut dyn Platform) -> HashMap<(String, String), SessionInfo> {
    plat.run("vtysh", &["-c", "show bgp vrf all summary json"])
        .ok()
        .filter(|o| o.ok)
        .map(|o| parse_bgp_summary(&o.stdout))
        .unwrap_or_default()
}

/// bgpmon's STATE_DB row for a peer (default VRF), the fallback when vtysh
/// gave nothing.
fn state_db_session(plat: &mut dyn Platform, peer: &str) -> Option<String> {
    field(&row(plat, STATE_DB, &format!("NEIGH_STATE_TABLE|{peer}")), "state")
        .map(str::to_string)
}

/// Normalize a CONFIG_DB admin_status field ("up"/"down" or "true"/"false")
/// to the contract's "up"/"down"; absent defaults to up (frrcfgd's default).
pub fn admin_of(h: &HashMap<String, String>) -> String {
    match field(h, "admin_status") {
        Some("down") | Some("false") => "down".to_string(),
        _ => "up".to_string(),
    }
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    let mode = p.bgp_mode();
    let cap = capability(mode);
    if mode == BgpMode::Unavailable {
        return Ok(json!({
            "capability": cap, "mode": mode.as_str(), "globals": [], "neighbors": [],
        }));
    }

    let (globals, mut neighbors) = match mode {
        BgpMode::Frrcfgd => read_frrcfgd(plat)?,
        _ => read_legacy(plat, &p)?,
    };

    let live = sessions(plat);
    for n in &mut neighbors {
        let info = live.get(&(n.vrf.clone(), n.peer.clone())).cloned().unwrap_or_default();
        n.session_state = info.state.or_else(|| {
            if n.vrf == "default" {
                state_db_session(plat, &n.peer)
            } else {
                None
            }
        });
        n.prefixes_received = info.prefixes_received;
        n.uptime_secs = info.uptime_secs;
    }

    Ok(json!({
        "capability": cap,
        "mode": mode.as_str(),
        "globals": globals,
        "neighbors": neighbors,
    }))
}

fn read_frrcfgd(
    plat: &mut dyn Platform,
) -> anyhow::Result<(Vec<GlobalDoc>, Vec<NeighborDoc>)> {
    let mut globals = Vec::new();
    for key in plat.scan(CONFIG_DB, "BGP_GLOBALS|*")? {
        // BGP_GLOBALS_AF also matches no prefix here: two-part keys only.
        let Some(vrf) = key_suffix(&key, "BGP_GLOBALS|") else { continue };
        if vrf.contains('|') {
            continue;
        }
        let r = row(plat, CONFIG_DB, &key);
        let af = row(plat, CONFIG_DB, &format!("BGP_GLOBALS_AF|{vrf}|ipv4_unicast"));
        globals.push(GlobalDoc {
            vrf: vrf.to_string(),
            local_asn: parse_num(field(&r, "local_asn")),
            router_id: field(&r, "router_id").map(str::to_string),
            keepalive: parse_num(field(&r, "keepalive")),
            holdtime: parse_num(field(&r, "holdtime")),
            graceful_restart: parse_bool(field(&r, "graceful_restart_enable")).unwrap_or(false),
            max_ebgp_paths: parse_num(field(&af, "max_ebgp_paths")),
            max_ibgp_paths: parse_num(field(&af, "max_ibgp_paths")),
        });
    }
    globals.sort_by(|a, b| a.vrf.cmp(&b.vrf));

    // AF enablement per (vrf, peer) first, one scan.
    let mut afs: HashMap<(String, String), Vec<&'static str>> = HashMap::new();
    for key in keys(plat, CONFIG_DB, "BGP_NEIGHBOR_AF|*") {
        let Some((vrf, peer, af)) = three_parts(&key, "BGP_NEIGHBOR_AF|") else { continue };
        let enabled = parse_bool(field(&row(plat, CONFIG_DB, &key), "admin_status"))
            .unwrap_or(true);
        if !enabled {
            continue;
        }
        let label = match af {
            "ipv4_unicast" => "ipv4_unicast",
            "ipv6_unicast" => "ipv6_unicast",
            "l2vpn_evpn" => "l2vpn_evpn",
            _ => continue,
        };
        afs.entry((vrf.to_string(), peer.to_string())).or_default().push(label);
    }

    let mut neighbors = Vec::new();
    for key in plat.scan(CONFIG_DB, "BGP_NEIGHBOR|*")? {
        // frrcfgd keys are BGP_NEIGHBOR|<vrf>|<peer>; skip flat legacy rows.
        let Some((vrf, peer)) = two_parts(&key, "BGP_NEIGHBOR|") else { continue };
        let r = row(plat, CONFIG_DB, &key);
        let mut families = afs.remove(&(vrf.to_string(), peer.to_string())).unwrap_or_default();
        families.sort();
        neighbors.push(NeighborDoc {
            vrf: vrf.to_string(),
            peer: peer.to_string(),
            remote_asn: parse_num(field(&r, "asn")),
            name: field(&r, "name").map(str::to_string),
            peer_group: field(&r, "peer_group_name").map(str::to_string),
            local_addr: field(&r, "local_addr").map(str::to_string),
            keepalive: parse_num(field(&r, "keepalive")),
            holdtime: parse_num(field(&r, "holdtime")),
            ebgp_multihop_ttl: parse_num(field(&r, "ebgp_multihop_ttl")),
            bfd: parse_bool(field(&r, "bfd")).unwrap_or(false),
            admin_status: admin_of(&r),
            address_families: families,
            session_state: None,
            prefixes_received: None,
            uptime_secs: None,
        });
    }
    neighbors.sort_by(|a, b| a.vrf.cmp(&b.vrf).then_with(|| a.peer.cmp(&b.peer)));
    Ok((globals, neighbors))
}

fn read_legacy(
    plat: &mut dyn Platform,
    p: &probe::Probe,
) -> anyhow::Result<(Vec<GlobalDoc>, Vec<NeighborDoc>)> {
    let mut globals = Vec::new();
    if let Some(asn) = p.bgp_asn {
        globals.push(GlobalDoc {
            vrf: "default".to_string(),
            local_asn: Some(asn),
            router_id: None,
            keepalive: None,
            holdtime: None,
            graceful_restart: false,
            max_ebgp_paths: None,
            max_ibgp_paths: None,
        });
    }
    let mut neighbors = Vec::new();
    for key in plat.scan(CONFIG_DB, "BGP_NEIGHBOR|*")? {
        let Some(peer) = key_suffix(&key, "BGP_NEIGHBOR|") else { continue };
        if peer.contains('|') {
            continue; // frrcfgd-style rows aren't ours in legacy mode
        }
        let r = row(plat, CONFIG_DB, &key);
        let af = if peer.contains(':') { "ipv6_unicast" } else { "ipv4_unicast" };
        neighbors.push(NeighborDoc {
            vrf: "default".to_string(),
            peer: peer.to_string(),
            remote_asn: parse_num(field(&r, "asn")),
            name: field(&r, "name").map(str::to_string),
            peer_group: None,
            local_addr: field(&r, "local_addr").map(str::to_string),
            keepalive: parse_num(field(&r, "keepalive")),
            holdtime: parse_num(field(&r, "holdtime")),
            ebgp_multihop_ttl: None,
            bfd: false,
            admin_status: admin_of(&r),
            address_families: vec![af],
            session_state: None,
            prefixes_received: None,
            uptime_secs: None,
        });
    }
    neighbors.sort_by(|a, b| a.peer.cmp(&b.peer));
    Ok((globals, neighbors))
}

// ── write plumbing ──────────────────────────────────────────────────────────

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

fn cannot(msg: impl Into<String>) -> WriteError {
    WriteError::Unprocessable(msg.into())
}

fn mode_for_writes(plat: &mut dyn Platform) -> std::result::Result<BgpMode, WriteError> {
    match probe::current(plat).bgp_mode() {
        BgpMode::Unavailable => Err(WriteError::Conflict(UNAVAILABLE_REASON.to_string())),
        m => Ok(m),
    }
}

fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// frrcfgd accepts IPs and interface names as peers ("unnumbered" BGP).
fn valid_peer(s: &str, allow_interface: bool) -> bool {
    is_ip(s)
        || (allow_interface
            && (s.starts_with("Ethernet") || s.starts_with("PortChannel") || s.starts_with("Vlan")))
}

fn valid_vrf(s: &str) -> bool {
    s == "default" || s.starts_with("Vrf")
}

fn check_asn(asn: u64) -> std::result::Result<(), String> {
    if (1..=4_294_967_295).contains(&asn) {
        Ok(())
    } else {
        Err(format!("invalid ASN {asn} (must be 1-4294967295)"))
    }
}

fn check_timers(keepalive: Option<u64>, holdtime: Option<u64>) -> std::result::Result<(), String> {
    if let Some(h) = holdtime {
        if h != 0 && !(3..=65_535).contains(&h) {
            return Err(format!("invalid holdtime {h} (must be 0 or 3-65535)"));
        }
    }
    if let Some(k) = keepalive {
        if !(1..=21_845).contains(&k) {
            return Err(format!("invalid keepalive {k} (must be 1-21845)"));
        }
    }
    if let (Some(k), Some(h)) = (keepalive, holdtime) {
        if h != 0 && k >= h {
            return Err(format!("keepalive {k} must be less than holdtime {h}"));
        }
    }
    Ok(())
}

fn is_dotted_quad(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}

// ── PUT /api/routing/bgp/globals/{vrf} ──────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GlobalInput {
    pub local_asn: Option<u64>,
    pub router_id: Option<String>,
    pub keepalive: Option<u64>,
    pub holdtime: Option<u64>,
    #[serde(default)]
    pub graceful_restart: bool,
    pub max_ebgp_paths: Option<u64>,
    pub max_ibgp_paths: Option<u64>,
}

pub fn put_global(plat: &mut dyn Platform, vrf: &str, input: &GlobalInput) -> WriteResult {
    let _lock = store::feature_lock("bgp");
    let mode = mode_for_writes(plat)?;
    if !valid_vrf(vrf) {
        return Err(bad(format!("invalid vrf {vrf:?} (default or Vrf…)")));
    }
    if let Some(asn) = input.local_asn {
        check_asn(asn).map_err(bad)?;
    }
    check_timers(input.keepalive, input.holdtime).map_err(bad)?;
    if let Some(rid) = &input.router_id {
        if !is_dotted_quad(rid) {
            return Err(bad(format!("invalid router_id {rid:?}")));
        }
    }

    if mode == BgpMode::Legacy {
        if vrf != "default" {
            return Err(cannot("legacy BGP supports the default VRF only".to_string()));
        }
        // DEVICE_METADATA.bgp_asn is the whole legacy global surface.
        let inexpressible = [
            ("router_id", input.router_id.is_some()),
            ("keepalive", input.keepalive.is_some()),
            ("holdtime", input.holdtime.is_some()),
            ("graceful_restart", input.graceful_restart),
            ("max_ebgp_paths", input.max_ebgp_paths.is_some()),
            ("max_ibgp_paths", input.max_ibgp_paths.is_some()),
        ];
        if let Some((name, _)) = inexpressible.iter().find(|(_, set)| *set) {
            return Err(cannot(format!(
                "{name} cannot be configured with the legacy BGP schema (enable \
                 frr_mgmt_framework_config for the full surface)"
            )));
        }
        return match input.local_asn {
            Some(asn) => plat
                .hset(CONFIG_DB, "DEVICE_METADATA|localhost", &[("bgp_asn", &asn.to_string())])
                .map_err(WriteError::Redis),
            None => plat
                .hdel(CONFIG_DB, "DEVICE_METADATA|localhost", &["bgp_asn"])
                .map_err(WriteError::Redis),
        };
    }

    // frrcfgd mode.
    if vrf != "default"
        && !plat.exists(CONFIG_DB, &format!("VRF|{vrf}")).map_err(WriteError::Redis)?
    {
        return Err(bad(format!("no such VRF {vrf}")));
    }
    let Some(asn) = input.local_asn else {
        // local_asn null removes the instance and everything under it.
        let mut doomed = vec![format!("BGP_GLOBALS|{vrf}")];
        for pattern in [
            format!("BGP_GLOBALS_AF|{vrf}|*"),
            format!("BGP_NEIGHBOR|{vrf}|*"),
            format!("BGP_NEIGHBOR_AF|{vrf}|*"),
        ] {
            doomed.extend(plat.scan(CONFIG_DB, &pattern).map_err(WriteError::Redis)?);
        }
        for key in doomed {
            plat.del(CONFIG_DB, &key).map_err(WriteError::Redis)?;
        }
        return Ok(());
    };

    store::apply(plat, |b| {
        let key = format!("BGP_GLOBALS|{vrf}");
        let asn_s = asn.to_string();
        b.hset(
            CONFIG_DB,
            &key,
            &[
                ("local_asn", asn_s.as_str()),
                ("graceful_restart_enable", if input.graceful_restart { "true" } else { "false" }),
            ],
        )?;
        for (fname, v) in [
            ("router_id", input.router_id.clone()),
            ("keepalive", input.keepalive.map(|v| v.to_string())),
            ("holdtime", input.holdtime.map(|v| v.to_string())),
        ] {
            match v {
                Some(v) => b.hset(CONFIG_DB, &key, &[(fname, v.as_str())])?,
                None => b.hdel(CONFIG_DB, &key, &[fname])?,
            }
        }
        // Multipath knobs live on the AF rows; keep v4 and v6 in step.
        for af in ["ipv4_unicast", "ipv6_unicast"] {
            let af_key = format!("BGP_GLOBALS_AF|{vrf}|{af}");
            for (fname, v) in
                [("max_ebgp_paths", input.max_ebgp_paths), ("max_ibgp_paths", input.max_ibgp_paths)]
            {
                match v {
                    Some(v) => b.hset(CONFIG_DB, &af_key, &[(fname, v.to_string().as_str())])?,
                    None => b.hdel(CONFIG_DB, &af_key, &[fname])?,
                }
            }
        }
        Ok(())
    })
    .map_err(WriteError::Redis)
}

// ── neighbors ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct NeighborInput {
    pub remote_asn: u64,
    pub name: Option<String>,
    pub peer_group: Option<String>,
    pub local_addr: Option<String>,
    pub keepalive: Option<u64>,
    pub holdtime: Option<u64>,
    pub ebgp_multihop_ttl: Option<u64>,
    #[serde(default)]
    pub bfd: bool,
    pub admin_status: AdminStatus,
    /// Full desired AF set.
    #[serde(default)]
    pub address_families: Vec<Af>,
}

#[derive(Debug, Deserialize)]
pub struct NeighborCreate {
    pub vrf: String,
    pub peer: String,
    #[serde(flatten)]
    pub input: NeighborInput,
}

fn check_neighbor_common(vrf: &str, input: &NeighborInput) -> WriteResult {
    if !valid_vrf(vrf) {
        return Err(bad(format!("invalid vrf {vrf:?} (default or Vrf…)")));
    }
    check_asn(input.remote_asn).map_err(bad)?;
    check_timers(input.keepalive, input.holdtime).map_err(bad)?;
    if let Some(ttl) = input.ebgp_multihop_ttl {
        if !(1..=255).contains(&ttl) {
            return Err(bad(format!("invalid ebgp_multihop_ttl {ttl} (must be 1-255)")));
        }
    }
    if let Some(addr) = &input.local_addr {
        if !is_ip(addr) {
            return Err(bad(format!("invalid local_addr {addr:?}")));
        }
    }
    Ok(())
}

pub fn create_neighbor(plat: &mut dyn Platform, create: &NeighborCreate) -> WriteResult {
    upsert_neighbor(plat, &create.vrf, &create.peer, &create.input, true)
}

pub fn put_neighbor(
    plat: &mut dyn Platform,
    vrf: &str,
    peer: &str,
    input: &NeighborInput,
) -> WriteResult {
    upsert_neighbor(plat, vrf, peer, input, false)
}

fn upsert_neighbor(
    plat: &mut dyn Platform,
    vrf: &str,
    peer: &str,
    input: &NeighborInput,
    creating: bool,
) -> WriteResult {
    let _lock = store::feature_lock("bgp");
    let mode = mode_for_writes(plat)?;
    check_neighbor_common(vrf, input)?;

    if mode == BgpMode::Legacy {
        return upsert_legacy_neighbor(plat, vrf, peer, input, creating);
    }

    if !valid_peer(peer, true) {
        return Err(bad(format!("invalid peer {peer:?} (IP address or interface)")));
    }
    let key = format!("BGP_NEIGHBOR|{vrf}|{peer}");
    let exists = plat.exists(CONFIG_DB, &key).map_err(WriteError::Redis)?;
    if creating && exists {
        return Err(bad(format!("neighbor {peer} already exists in vrf {vrf}")));
    }
    if !creating && !exists {
        return Err(WriteError::NotFound(format!("no such neighbor {peer} in vrf {vrf}")));
    }
    if !plat.exists(CONFIG_DB, &format!("BGP_GLOBALS|{vrf}")).map_err(WriteError::Redis)? {
        return Err(bad(format!(
            "no BGP instance for vrf {vrf} (set its local_asn first)"
        )));
    }
    if let Some(group) = &input.peer_group {
        if group.is_empty() {
            return Err(bad("peer_group must not be empty".to_string()));
        }
    }

    let current_afs: Vec<String> =
        keys(plat, CONFIG_DB, &format!("BGP_NEIGHBOR_AF|{vrf}|{peer}|*"));
    let desired: BTreeSet<&'static str> =
        input.address_families.iter().map(|af| af.as_str()).collect();
    store::apply(plat, |b| {
        let asn_s = input.remote_asn.to_string();
        b.hset(
            CONFIG_DB,
            &key,
            &[
                ("asn", asn_s.as_str()),
                ("bfd", if input.bfd { "true" } else { "false" }),
                ("admin_status", input.admin_status.as_str()),
            ],
        )?;
        for (fname, v) in [
            ("name", input.name.clone()),
            ("peer_group_name", input.peer_group.clone()),
            ("local_addr", input.local_addr.clone()),
            ("keepalive", input.keepalive.map(|v| v.to_string())),
            ("holdtime", input.holdtime.map(|v| v.to_string())),
            ("ebgp_multihop_ttl", input.ebgp_multihop_ttl.map(|v| v.to_string())),
        ] {
            match v {
                Some(v) => b.hset(CONFIG_DB, &key, &[(fname, v.as_str())])?,
                None => b.hdel(CONFIG_DB, &key, &[fname])?,
            }
        }
        // Converge the AF rows to the full desired set.
        let af_prefix = format!("BGP_NEIGHBOR_AF|{vrf}|{peer}|");
        for existing in &current_afs {
            let Some(af) = existing.strip_prefix(&af_prefix) else { continue };
            if !desired.contains(af) {
                b.del(CONFIG_DB, existing)?;
            }
        }
        for af in &desired {
            b.hset(CONFIG_DB, &format!("{af_prefix}{af}"), &[("admin_status", "true")])?;
        }
        Ok(())
    })
    .map_err(WriteError::Redis)
}

fn upsert_legacy_neighbor(
    plat: &mut dyn Platform,
    vrf: &str,
    peer: &str,
    input: &NeighborInput,
    creating: bool,
) -> WriteResult {
    if vrf != "default" {
        return Err(cannot("legacy BGP supports the default VRF only".to_string()));
    }
    if !is_ip(peer) {
        return Err(bad(format!(
            "invalid peer {peer:?} (legacy BGP accepts IP addresses only)"
        )));
    }
    // The flat schema simply has nowhere to put these.
    let inexpressible = [
        ("peer_group", input.peer_group.is_some()),
        ("ebgp_multihop_ttl", input.ebgp_multihop_ttl.is_some()),
        ("bfd", input.bfd),
    ];
    if let Some((name, _)) = inexpressible.iter().find(|(_, set)| *set) {
        return Err(cannot(format!(
            "{name} cannot be configured with the legacy BGP schema (enable \
             frr_mgmt_framework_config for the full surface)"
        )));
    }
    let implied = if peer.contains(':') { Af::Ipv6Unicast } else { Af::Ipv4Unicast };
    if !input.address_families.is_empty() && input.address_families != vec![implied] {
        return Err(cannot(format!(
            "legacy BGP activates exactly the peer's own address family ({})",
            implied.as_str()
        )));
    }
    let meta = row(plat, CONFIG_DB, "DEVICE_METADATA|localhost");
    if field(&meta, "bgp_asn").is_none() {
        return Err(WriteError::Conflict(
            "set the local ASN (PUT /api/routing/bgp/globals/default) before adding neighbors"
                .to_string(),
        ));
    }
    let key = format!("BGP_NEIGHBOR|{peer}");
    let exists = plat.exists(CONFIG_DB, &key).map_err(WriteError::Redis)?;
    if creating && exists {
        return Err(bad(format!("neighbor {peer} already exists")));
    }
    if !creating && !exists {
        return Err(WriteError::NotFound(format!("no such neighbor {peer}")));
    }
    store::apply(plat, |b| {
        let asn_s = input.remote_asn.to_string();
        b.hset(
            CONFIG_DB,
            &key,
            &[("asn", asn_s.as_str()), ("admin_status", input.admin_status.as_str())],
        )?;
        for (fname, v) in [
            ("name", input.name.clone()),
            ("local_addr", input.local_addr.clone()),
            ("keepalive", input.keepalive.map(|v| v.to_string())),
            ("holdtime", input.holdtime.map(|v| v.to_string())),
        ] {
            match v {
                Some(v) => b.hset(CONFIG_DB, &key, &[(fname, v.as_str())])?,
                None => b.hdel(CONFIG_DB, &key, &[fname])?,
            }
        }
        Ok(())
    })
    .map_err(WriteError::Redis)
}

pub fn delete_neighbor(plat: &mut dyn Platform, vrf: &str, peer: &str) -> WriteResult {
    let _lock = store::feature_lock("bgp");
    let mode = mode_for_writes(plat)?;
    if mode == BgpMode::Legacy {
        if vrf != "default" {
            return Err(cannot("legacy BGP supports the default VRF only".to_string()));
        }
        let key = format!("BGP_NEIGHBOR|{peer}");
        if !plat.exists(CONFIG_DB, &key).map_err(WriteError::Redis)? {
            return Err(WriteError::NotFound(format!("no such neighbor {peer}")));
        }
        return plat.del(CONFIG_DB, &key).map_err(WriteError::Redis);
    }
    let key = format!("BGP_NEIGHBOR|{vrf}|{peer}");
    if !plat.exists(CONFIG_DB, &key).map_err(WriteError::Redis)? {
        return Err(WriteError::NotFound(format!("no such neighbor {peer} in vrf {vrf}")));
    }
    for af_key in plat
        .scan(CONFIG_DB, &format!("BGP_NEIGHBOR_AF|{vrf}|{peer}|*"))
        .map_err(WriteError::Redis)?
    {
        plat.del(CONFIG_DB, &af_key).map_err(WriteError::Redis)?;
    }
    plat.del(CONFIG_DB, &key).map_err(WriteError::Redis)
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::*;

    fn frrcfgd() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202505.1'\n");
        m.seed(CONFIG_DB, "FEATURE|bgp", &[("state", "enabled")]);
        m.seed(
            CONFIG_DB,
            "DEVICE_METADATA|localhost",
            &[("frr_mgmt_framework_config", "true"), ("bgp_asn", "65100")],
        );
        m
    }

    fn legacy() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        m.seed(CONFIG_DB, "FEATURE|bgp", &[("state", "enabled")]);
        m.seed(CONFIG_DB, "DEVICE_METADATA|localhost", &[("bgp_asn", "65100")]);
        m
    }

    fn neighbor_input(asn: u64, afs: &[Af]) -> NeighborInput {
        NeighborInput {
            remote_asn: asn,
            name: None,
            peer_group: None,
            local_addr: None,
            keepalive: None,
            holdtime: None,
            ebgp_multihop_ttl: None,
            bfd: false,
            admin_status: AdminStatus::Up,
            address_families: afs.to_vec(),
        }
    }

    #[test]
    fn unavailable_without_bgp_feature() {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        m.seed(CONFIG_DB, "FEATURE|lldp", &[("state", "enabled")]);
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["mode"], "unavailable");
        assert_eq!(doc["capability"]["supported"], false);
        let err = put_global(
            &mut m,
            "default",
            &GlobalInput {
                local_asn: Some(65000),
                router_id: None,
                keepalive: None,
                holdtime: None,
                graceful_restart: false,
                max_ebgp_paths: None,
                max_ibgp_paths: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
        // Nothing landed in the inert tables.
        assert!(!m.has_key(CONFIG_DB, "BGP_GLOBALS|default"));
    }

    #[test]
    fn frrcfgd_reads_three_part_schema() {
        let mut m = frrcfgd();
        m.seed(
            CONFIG_DB,
            "BGP_GLOBALS|default",
            &[("local_asn", "65100"), ("router_id", "10.0.0.1"), ("graceful_restart_enable", "true")],
        );
        m.seed(CONFIG_DB, "BGP_GLOBALS_AF|default|ipv4_unicast", &[("max_ebgp_paths", "8")]);
        m.seed(
            CONFIG_DB,
            "BGP_NEIGHBOR|default|10.0.0.2",
            &[("asn", "65200"), ("name", "spine1"), ("bfd", "true"), ("admin_status", "up")],
        );
        m.seed(
            CONFIG_DB,
            "BGP_NEIGHBOR_AF|default|10.0.0.2|ipv4_unicast",
            &[("admin_status", "true")],
        );
        m.seed(
            CONFIG_DB,
            "BGP_NEIGHBOR_AF|default|10.0.0.2|l2vpn_evpn",
            &[("admin_status", "true")],
        );
        m.seed(STATE_DB, "NEIGH_STATE_TABLE|10.0.0.2", &[("state", "Established")]);
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["mode"], "frrcfgd");
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["globals"][0]["local_asn"], 65100);
        assert_eq!(doc["globals"][0]["graceful_restart"], true);
        assert_eq!(doc["globals"][0]["max_ebgp_paths"], 8);
        let n = &doc["neighbors"][0];
        assert_eq!(n["peer"], "10.0.0.2");
        assert_eq!(n["remote_asn"], 65200);
        assert_eq!(n["bfd"], true);
        assert_eq!(n["address_families"], json!(["ipv4_unicast", "l2vpn_evpn"]));
        // vtysh gave nothing (mock returns empty) → bgpmon state fills in.
        assert_eq!(n["session_state"], "Established");
    }

    #[test]
    fn vtysh_summary_parses_and_merges() {
        let text = r#"{
            "default": {
                "ipv4Unicast": {"peers": {"10.0.0.2": {"state": "Established", "pfxRcd": 12, "peerUptimeMsec": 5500}}},
                "ipv6Unicast": {"peers": {"10.0.0.2": {"state": "Established", "pfxRcd": 3, "peerUptimeMsec": 5500}}}
            },
            "VrfBlue": {"ipv4Unicast": {"peers": {"192.168.1.1": {"state": "Active", "pfxRcd": 0}}}}
        }"#;
        let map = parse_bgp_summary(text);
        let d = map.get(&("default".to_string(), "10.0.0.2".to_string())).unwrap();
        assert_eq!(d.state.as_deref(), Some("Established"));
        assert_eq!(d.prefixes_received, Some(15)); // summed across AFs
        assert_eq!(d.uptime_secs, Some(5));
        let b = map.get(&("VrfBlue".to_string(), "192.168.1.1".to_string())).unwrap();
        assert_eq!(b.state.as_deref(), Some("Active"));
        assert!(parse_bgp_summary("not json").is_empty());
        assert!(parse_bgp_summary("{}").is_empty());
    }

    #[test]
    fn frrcfgd_neighbor_af_full_set_diff() {
        let mut m = frrcfgd();
        m.seed(CONFIG_DB, "BGP_GLOBALS|default", &[("local_asn", "65100")]);
        m.seed(CONFIG_DB, "BGP_NEIGHBOR|default|10.0.0.2", &[("asn", "65200")]);
        m.seed(
            CONFIG_DB,
            "BGP_NEIGHBOR_AF|default|10.0.0.2|ipv4_unicast",
            &[("admin_status", "true")],
        );
        m.seed(
            CONFIG_DB,
            "BGP_NEIGHBOR_AF|default|10.0.0.2|l2vpn_evpn",
            &[("admin_status", "true")],
        );
        // Desired set swaps l2vpn_evpn for ipv6_unicast; ipv4 stays.
        put_neighbor(
            &mut m,
            "default",
            "10.0.0.2",
            &neighbor_input(65200, &[Af::Ipv4Unicast, Af::Ipv6Unicast]),
        )
        .unwrap();
        assert!(m.has_key(CONFIG_DB, "BGP_NEIGHBOR_AF|default|10.0.0.2|ipv4_unicast"));
        assert!(m.has_key(CONFIG_DB, "BGP_NEIGHBOR_AF|default|10.0.0.2|ipv6_unicast"));
        assert!(!m.has_key(CONFIG_DB, "BGP_NEIGHBOR_AF|default|10.0.0.2|l2vpn_evpn"));
    }

    #[test]
    fn frrcfgd_neighbor_requires_instance_and_valid_peer() {
        let mut m = frrcfgd();
        let err = create_neighbor(
            &mut m,
            &NeighborCreate {
                vrf: "default".into(),
                peer: "10.0.0.9".into(),
                input: neighbor_input(65001, &[Af::Ipv4Unicast]),
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)), "{err:?}");
        m.seed(CONFIG_DB, "BGP_GLOBALS|default", &[("local_asn", "65100")]);
        let err = create_neighbor(
            &mut m,
            &NeighborCreate {
                vrf: "default".into(),
                peer: "not-a-peer".into(),
                input: neighbor_input(65001, &[Af::Ipv4Unicast]),
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
        // Interface peers are fine under frrcfgd.
        create_neighbor(
            &mut m,
            &NeighborCreate {
                vrf: "default".into(),
                peer: "Ethernet0".into(),
                input: neighbor_input(65001, &[Af::Ipv4Unicast]),
            },
        )
        .unwrap();
        assert!(m.has_key(CONFIG_DB, "BGP_NEIGHBOR|default|Ethernet0"));
    }

    #[test]
    fn frrcfgd_instance_teardown_on_null_asn() {
        let mut m = frrcfgd();
        m.seed(CONFIG_DB, "VRF|VrfBlue", &[("fallback", "false")]);
        m.seed(CONFIG_DB, "BGP_GLOBALS|VrfBlue", &[("local_asn", "65100")]);
        m.seed(CONFIG_DB, "BGP_GLOBALS_AF|VrfBlue|ipv4_unicast", &[("max_ebgp_paths", "4")]);
        m.seed(CONFIG_DB, "BGP_NEIGHBOR|VrfBlue|10.1.0.1", &[("asn", "65001")]);
        m.seed(
            CONFIG_DB,
            "BGP_NEIGHBOR_AF|VrfBlue|10.1.0.1|ipv4_unicast",
            &[("admin_status", "true")],
        );
        put_global(
            &mut m,
            "VrfBlue",
            &GlobalInput {
                local_asn: None,
                router_id: None,
                keepalive: None,
                holdtime: None,
                graceful_restart: false,
                max_ebgp_paths: None,
                max_ibgp_paths: None,
            },
        )
        .unwrap();
        assert!(!m.has_key(CONFIG_DB, "BGP_GLOBALS|VrfBlue"));
        assert!(!m.has_key(CONFIG_DB, "BGP_GLOBALS_AF|VrfBlue|ipv4_unicast"));
        assert!(!m.has_key(CONFIG_DB, "BGP_NEIGHBOR|VrfBlue|10.1.0.1"));
        assert!(!m.has_key(CONFIG_DB, "BGP_NEIGHBOR_AF|VrfBlue|10.1.0.1|ipv4_unicast"));
    }

    #[test]
    fn legacy_reads_flat_schema_and_reports_reduced_surface() {
        let mut m = legacy();
        m.seed(
            CONFIG_DB,
            "BGP_NEIGHBOR|10.0.0.2",
            &[("asn", "65200"), ("name", "spine1"), ("holdtime", "180"), ("admin_status", "up")],
        );
        m.seed(CONFIG_DB, "BGP_NEIGHBOR|fc00::2", &[("asn", "65201")]);
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["mode"], "legacy");
        assert_eq!(doc["capability"]["supported"], true);
        assert!(doc["capability"]["reason"].as_str().unwrap().contains("legacy"));
        assert_eq!(doc["globals"][0]["local_asn"], 65100);
        let v4 = &doc["neighbors"][0];
        assert_eq!(v4["peer"], "10.0.0.2");
        assert_eq!(v4["address_families"], json!(["ipv4_unicast"]));
        let v6 = &doc["neighbors"][1];
        assert_eq!(v6["peer"], "fc00::2");
        assert_eq!(v6["address_families"], json!(["ipv6_unicast"]));
    }

    #[test]
    fn legacy_rejects_inexpressible_fields() {
        let mut m = legacy();
        let mut input = neighbor_input(65200, &[]);
        input.bfd = true;
        let err = create_neighbor(
            &mut m,
            &NeighborCreate { vrf: "default".into(), peer: "10.0.0.2".into(), input },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Unprocessable(_)));
        // Interface peers only work under frrcfgd.
        let err = create_neighbor(
            &mut m,
            &NeighborCreate {
                vrf: "default".into(),
                peer: "Ethernet0".into(),
                input: neighbor_input(65200, &[]),
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
        // Non-default vrf → 422.
        let err = put_global(
            &mut m,
            "VrfBlue",
            &GlobalInput {
                local_asn: Some(65000),
                router_id: None,
                keepalive: None,
                holdtime: None,
                graceful_restart: false,
                max_ebgp_paths: None,
                max_ibgp_paths: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Unprocessable(_)));
        // A clean legacy write works and lands in the flat schema.
        create_neighbor(
            &mut m,
            &NeighborCreate {
                vrf: "default".into(),
                peer: "10.0.0.2".into(),
                input: neighbor_input(65200, &[Af::Ipv4Unicast]),
            },
        )
        .unwrap();
        assert_eq!(m.row(CONFIG_DB, "BGP_NEIGHBOR|10.0.0.2").get("asn").unwrap(), "65200");
        assert!(!m.has_key(CONFIG_DB, "BGP_NEIGHBOR|default|10.0.0.2"));
    }

    #[test]
    fn delete_removes_af_rows_too() {
        let mut m = frrcfgd();
        m.seed(CONFIG_DB, "BGP_NEIGHBOR|default|10.0.0.2", &[("asn", "65200")]);
        m.seed(
            CONFIG_DB,
            "BGP_NEIGHBOR_AF|default|10.0.0.2|ipv4_unicast",
            &[("admin_status", "true")],
        );
        delete_neighbor(&mut m, "default", "10.0.0.2").unwrap();
        assert!(!m.has_key(CONFIG_DB, "BGP_NEIGHBOR|default|10.0.0.2"));
        assert!(!m.has_key(CONFIG_DB, "BGP_NEIGHBOR_AF|default|10.0.0.2|ipv4_unicast"));
        let err = delete_neighbor(&mut m, "default", "10.0.0.2").unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
    }

    #[test]
    fn timer_and_asn_validation() {
        assert!(check_timers(Some(60), Some(180)).is_ok());
        assert!(check_timers(Some(180), Some(60)).is_err());
        assert!(check_timers(None, Some(1)).is_err());
        assert!(check_timers(Some(30), Some(0)).is_ok()); // holdtime 0 = disabled
        assert!(check_asn(0).is_err());
        assert!(check_asn(65100).is_ok());
    }
}
