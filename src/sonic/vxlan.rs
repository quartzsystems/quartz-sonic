//! VXLAN / EVPN overlay for the console's Configure → Routing → VXLAN page.
//!
//! Config side: the switch's single VTEP (CONFIG_DB `VXLAN_TUNNEL`), the
//! EVPN NVO binding (`EVPN_NVO`), and the VLAN↔VNI map (`VXLAN_TUNNEL_MAP`,
//! keys `{vtep}|map_{vni}_Vlan{id}`). Status side: remote VTEPs and tunnel
//! oper state from STATE_DB `VXLAN_TUNNEL_TABLE` (EVPN-learned tunnels are
//! keyed `EVPN_{ip}`) and APPL_DB `VXLAN_REMOTE_VNI_TABLE`. VXLAN needs a
//! 202012+ orchagent; binding the VTEP to EVPN additionally needs FRR.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use serde::Deserialize;
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, field, key_suffix, keys, row, two_parts, Platform};
use super::switching::{WriteError, WriteResult};
use super::{APPL_DB, CONFIG_DB, STATE_DB};

const UNSUPPORTED: &str =
    "VXLAN requires SONiC 202012 or newer; this image's orchagent does not handle VXLAN_TUNNEL";
const EVPN_NEEDS_FRR: &str = "binding the VTEP to EVPN requires FRR with EVPN support \
     (the bgp container), which is not running on this image";

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

/// The switch's VTEP as (name, source_ip); SONiC supports one per switch.
fn vtep_row(plat: &mut dyn Platform) -> Option<(String, String)> {
    let mut ks = keys(plat, CONFIG_DB, "VXLAN_TUNNEL|*");
    ks.sort();
    for k in ks {
        if let Some(name) = key_suffix(&k, "VXLAN_TUNNEL|") {
            if name.contains('|') {
                continue;
            }
            let name = name.to_string();
            let src = field(&row(plat, CONFIG_DB, &k), "src_ip").unwrap_or("").to_string();
            return Some((name, src));
        }
    }
    None
}

/// (vlan_id, vni) from a VXLAN_TUNNEL_MAP entry — the row's fields first,
/// the `map_{vni}_Vlan{id}` key name as fallback. Pure.
pub fn parse_map(map_name: &str, cfg: &HashMap<String, String>) -> Option<(u32, u32)> {
    let from_key = || -> Option<(u32, u32)> {
        let rest = map_name.strip_prefix("map_")?;
        let (vni, vlan) = rest.split_once("_Vlan")?;
        Some((vlan.parse().ok()?, vni.parse().ok()?))
    };
    let vlan = field(cfg, "vlan").and_then(|v| v.strip_prefix("Vlan")).and_then(|v| v.parse().ok());
    let vni = field(cfg, "vni").and_then(|v| v.parse().ok());
    match (vlan, vni) {
        (Some(vlan), Some(vni)) => Some((vlan, vni)),
        _ => from_key(),
    }
}

/// The configured VLAN↔VNI maps, sorted by VLAN.
fn config_maps(plat: &mut dyn Platform) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for key in keys(plat, CONFIG_DB, "VXLAN_TUNNEL_MAP|*") {
        let Some((_, map_name)) = two_parts(&key, "VXLAN_TUNNEL_MAP|") else { continue };
        let cfg = row(plat, CONFIG_DB, &key);
        if let Some(m) = parse_map(map_name, &cfg) {
            out.push(m);
        }
    }
    out.sort();
    out
}

fn valid_object_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn capability_of(p: &probe::Probe) -> Capability {
    if p.bgp_available() {
        Capability::yes()
    } else {
        // VXLAN works; the reason just flags the EVPN limitation for the UI.
        Capability::yes_with_reason(EVPN_NEEDS_FRR)
    }
}

// ── GET /api/routing/vxlan ──────────────────────────────────────────────────

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    if !p.vxlan_supported() {
        return Ok(json!({
            "capability": Capability::no(UNSUPPORTED),
            "vtep": null, "evpn_nvo": false, "vlan_vni_maps": [],
        }));
    }
    let vtep = vtep_row(plat);
    let evpn_nvo = !keys(plat, CONFIG_DB, "EVPN_NVO|*").is_empty();
    let maps: Vec<_> = config_maps(plat)
        .iter()
        .map(|(vlan, vni)| json!({ "vlan_id": vlan, "vni": vni }))
        .collect();
    Ok(json!({
        "capability": capability_of(&p),
        "vtep": vtep.as_ref().map(|(n, s)| json!({ "name": n, "source_ip": s })),
        "evpn_nvo": evpn_nvo,
        "vlan_vni_maps": maps,
    }))
}

// ── PUT /api/routing/vxlan/vtep ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct VtepInput {
    pub name: String,
    pub source_ip: String,
    pub evpn_nvo: bool,
}

pub fn put_vtep(plat: &mut dyn Platform, input: &VtepInput) -> WriteResult {
    let _lock = store::feature_lock("vxlan");
    if !valid_object_name(&input.name) {
        return Err(bad(format!("invalid VTEP name {:?}", input.name)));
    }
    input
        .source_ip
        .parse::<IpAddr>()
        .map_err(|_| bad(format!("invalid source_ip {:?}", input.source_ip)))?;
    let p = probe::current(plat);
    if !p.vxlan_supported() {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    if input.evpn_nvo && !p.bgp_available() {
        return Err(WriteError::Conflict(EVPN_NEEDS_FRR.to_string()));
    }
    if let Some((cur, _)) = vtep_row(plat) {
        if cur != input.name {
            if !keys(plat, CONFIG_DB, "VXLAN_TUNNEL_MAP|*").is_empty() {
                return Err(WriteError::Conflict(format!(
                    "cannot rename VTEP {cur} while VLAN-VNI maps exist; remove the maps first"
                )));
            }
            plat.del(CONFIG_DB, &format!("VXLAN_TUNNEL|{cur}"))?;
        }
    }
    // Recreate the row so a source_ip change is a clean replace.
    let key = format!("VXLAN_TUNNEL|{}", input.name);
    plat.del(CONFIG_DB, &key)?;
    plat.hset(CONFIG_DB, &key, &[("src_ip", input.source_ip.as_str())])?;
    for k in keys(plat, CONFIG_DB, "EVPN_NVO|*") {
        plat.del(CONFIG_DB, &k)?;
    }
    if input.evpn_nvo {
        plat.hset(CONFIG_DB, "EVPN_NVO|nvo", &[("source_vtep", input.name.as_str())])?;
    }
    Ok(())
}

// ── DELETE /api/routing/vxlan/vtep ──────────────────────────────────────────

pub fn delete_vtep(plat: &mut dyn Platform) -> WriteResult {
    let _lock = store::feature_lock("vxlan");
    let Some((name, _)) = vtep_row(plat) else {
        return Err(WriteError::NotFound("no VTEP is configured".into()));
    };
    let maps = keys(plat, CONFIG_DB, "VXLAN_TUNNEL_MAP|*");
    if !maps.is_empty() {
        return Err(WriteError::Conflict(format!(
            "VTEP {name} still has {} VLAN-VNI map(s); remove the maps first",
            maps.len()
        )));
    }
    for k in keys(plat, CONFIG_DB, "EVPN_NVO|*") {
        plat.del(CONFIG_DB, &k)?;
    }
    plat.del(CONFIG_DB, &format!("VXLAN_TUNNEL|{name}"))?;
    Ok(())
}

// ── PUT /api/routing/vxlan/maps ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct MapEntry {
    pub vlan_id: u32,
    pub vni: u32,
}

/// The full desired VLAN↔VNI set — the agent diffs against VXLAN_TUNNEL_MAP.
#[derive(Debug, Deserialize)]
pub struct MapsInput {
    pub maps: Vec<MapEntry>,
}

pub fn put_maps(plat: &mut dyn Platform, input: &MapsInput) -> WriteResult {
    let _lock = store::feature_lock("vxlan");
    let mut vlans = BTreeSet::new();
    let mut vnis = BTreeSet::new();
    for m in &input.maps {
        if !(1..=4094).contains(&m.vlan_id) {
            return Err(bad(format!("invalid vlan_id {} (must be 1-4094)", m.vlan_id)));
        }
        if !(1..=16_777_215).contains(&m.vni) {
            return Err(bad(format!("invalid vni {} (must be 1-16777215)", m.vni)));
        }
        if !vlans.insert(m.vlan_id) {
            return Err(bad(format!("VLAN {} is mapped twice", m.vlan_id)));
        }
        if !vnis.insert(m.vni) {
            return Err(bad(format!("VNI {} is mapped to two VLANs", m.vni)));
        }
    }
    if !probe::current(plat).vxlan_supported() {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    let Some((vtep, _)) = vtep_row(plat) else {
        return Err(WriteError::Conflict(
            "configure a VTEP before mapping VLANs to VNIs".to_string(),
        ));
    };
    for m in &input.maps {
        if !plat.exists(CONFIG_DB, &format!("VLAN|Vlan{}", m.vlan_id))? {
            return Err(bad(format!("VLAN {} does not exist", m.vlan_id)));
        }
    }
    let desired: BTreeMap<String, (String, String)> = input
        .maps
        .iter()
        .map(|m| {
            (
                format!("VXLAN_TUNNEL_MAP|{vtep}|map_{}_Vlan{}", m.vni, m.vlan_id),
                (format!("Vlan{}", m.vlan_id), m.vni.to_string()),
            )
        })
        .collect();
    for key in keys(plat, CONFIG_DB, "VXLAN_TUNNEL_MAP|*") {
        if !desired.contains_key(&key) {
            plat.del(CONFIG_DB, &key)?;
        }
    }
    for (key, (vlan, vni)) in &desired {
        plat.hset(CONFIG_DB, key, &[("vlan", vlan.as_str()), ("vni", vni.as_str())])?;
    }
    Ok(())
}

// ── GET /api/routing/vxlan/status ───────────────────────────────────────────

pub fn get_status(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    if !p.vxlan_supported() {
        return Ok(json!({
            "capability": Capability::no(UNSUPPORTED),
            "vtep": null, "remote_vteps": [], "mappings": [],
        }));
    }
    let vtep = vtep_row(plat);

    #[derive(Default)]
    struct Remote {
        oper: Option<&'static str>,
        source: Option<&'static str>,
        vnis: BTreeSet<u32>,
    }
    let mut remotes: BTreeMap<String, Remote> = BTreeMap::new();
    let mut local_oper: Option<&'static str> = None;
    for key in keys(plat, STATE_DB, "VXLAN_TUNNEL_TABLE|*") {
        let Some(name) = key_suffix(&key, "VXLAN_TUNNEL_TABLE|") else { continue };
        let name = name.to_string();
        let st = row(plat, STATE_DB, &key);
        let oper = match field(&st, "operstatus").map(str::to_ascii_lowercase).as_deref() {
            Some(s) if s.contains("up") => Some("up"),
            Some(s) if s.contains("down") => Some("down"),
            _ => None,
        };
        if let Some(ip) = name.strip_prefix("EVPN_") {
            let r = remotes.entry(ip.to_string()).or_default();
            r.oper = oper;
            r.source = Some("evpn");
        } else if Some(name.as_str()) == vtep.as_ref().map(|(n, _)| n.as_str()) {
            local_oper = oper;
        } else if let Some(dst) = field(&st, "dst_ip") {
            let r = remotes.entry(dst.to_string()).or_default();
            r.oper = oper;
            r.source = Some("static");
        }
    }
    // Which VNIs ride toward each remote, when the image reports them.
    let cfg_maps: HashMap<u32, u32> = config_maps(plat).into_iter().collect();
    for key in keys(plat, APPL_DB, "VXLAN_REMOTE_VNI_TABLE:*") {
        let Some(rest) = key.strip_prefix("VXLAN_REMOTE_VNI_TABLE:") else { continue };
        let Some((vlan, ip)) = rest.split_once(':') else { continue };
        let vlan = vlan.to_string();
        let ip = ip.to_string();
        let vni = field(&row(plat, APPL_DB, &key), "vni")
            .and_then(|v| v.parse().ok())
            .or_else(|| {
                let id: u32 = vlan.strip_prefix("Vlan")?.parse().ok()?;
                cfg_maps.get(&id).copied()
            });
        let r = remotes.entry(ip).or_default();
        if r.source.is_none() {
            r.source = Some("evpn");
        }
        if let Some(vni) = vni {
            r.vnis.insert(vni);
        }
    }
    let remote_docs: Vec<_> = remotes
        .iter()
        .map(|(ip, r)| {
            json!({
                "ip": ip,
                "oper_status": r.oper.unwrap_or("unknown"),
                "source": r.source.unwrap_or("unknown"),
                "vnis": r.vnis.iter().collect::<Vec<_>>(),
            })
        })
        .collect();
    // The image doesn't expose per-mapping oper state — the local tunnel's
    // status speaks for the mappings riding it.
    let mappings: Vec<_> = config_maps(plat)
        .iter()
        .map(|(vlan, vni)| {
            json!({
                "vlan_id": vlan, "vni": vni,
                "oper_status": local_oper.unwrap_or("unknown"),
            })
        })
        .collect();
    Ok(json!({
        "capability": capability_of(&p),
        "vtep": vtep.as_ref().map(|(n, s)| json!({ "name": n, "source_ip": s })),
        "remote_vteps": remote_docs,
        "mappings": mappings,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::*;

    fn platform() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        m.seed(CONFIG_DB, "FEATURE|bgp", &[("state", "enabled")]);
        m.seed(CONFIG_DB, "VLAN|Vlan10", &[("vlanid", "10")]);
        m.seed(CONFIG_DB, "VLAN|Vlan20", &[("vlanid", "20")]);
        m
    }

    fn vtep() -> VtepInput {
        VtepInput { name: "vtep1".into(), source_ip: "10.0.0.11".into(), evpn_nvo: true }
    }

    #[test]
    fn get_empty_document() {
        let mut m = platform();
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["vtep"], serde_json::Value::Null);
        assert_eq!(doc["evpn_nvo"], false);
        assert_eq!(doc["vlan_vni_maps"], json!([]));
    }

    #[test]
    fn unsupported_before_202012() {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '201911.1'\n");
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        assert!(matches!(put_vtep(&mut m, &vtep()).unwrap_err(), WriteError::Conflict(_)));
    }

    #[test]
    fn put_vtep_writes_tunnel_and_nvo() {
        let mut m = platform();
        put_vtep(&mut m, &vtep()).unwrap();
        assert_eq!(m.row(CONFIG_DB, "VXLAN_TUNNEL|vtep1").get("src_ip").unwrap(), "10.0.0.11");
        assert_eq!(m.row(CONFIG_DB, "EVPN_NVO|nvo").get("source_vtep").unwrap(), "vtep1");
        // source_ip changes recreate the row; dropping evpn_nvo removes the binding.
        let update = VtepInput { source_ip: "10.0.0.99".into(), evpn_nvo: false, ..vtep() };
        put_vtep(&mut m, &update).unwrap();
        assert_eq!(m.row(CONFIG_DB, "VXLAN_TUNNEL|vtep1").get("src_ip").unwrap(), "10.0.0.99");
        assert!(!m.has_key(CONFIG_DB, "EVPN_NVO|nvo"));
    }

    #[test]
    fn evpn_nvo_needs_frr() {
        let mut m = platform();
        m.del(CONFIG_DB, "FEATURE|bgp").unwrap();
        let err = put_vtep(&mut m, &vtep()).unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
        // The document still reads supported, with the limitation as reason.
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert!(doc["capability"]["reason"].as_str().unwrap().contains("EVPN"));
        // Without the binding the VTEP itself is fine.
        put_vtep(&mut m, &VtepInput { evpn_nvo: false, ..vtep() }).unwrap();
    }

    #[test]
    fn rename_guarded_by_maps() {
        let mut m = platform();
        put_vtep(&mut m, &vtep()).unwrap();
        put_maps(&mut m, &MapsInput { maps: vec![MapEntry { vlan_id: 10, vni: 10010 }] }).unwrap();
        let renamed = VtepInput { name: "vtep2".into(), ..vtep() };
        assert!(matches!(put_vtep(&mut m, &renamed).unwrap_err(), WriteError::Conflict(_)));
        // Without maps the rename replaces the old row.
        put_maps(&mut m, &MapsInput { maps: vec![] }).unwrap();
        put_vtep(&mut m, &renamed).unwrap();
        assert!(!m.has_key(CONFIG_DB, "VXLAN_TUNNEL|vtep1"));
        assert!(m.has_key(CONFIG_DB, "VXLAN_TUNNEL|vtep2"));
    }

    #[test]
    fn maps_diff_against_config_db() {
        let mut m = platform();
        put_vtep(&mut m, &vtep()).unwrap();
        put_maps(
            &mut m,
            &MapsInput {
                maps: vec![MapEntry { vlan_id: 10, vni: 10010 }, MapEntry { vlan_id: 20, vni: 10020 }],
            },
        )
        .unwrap();
        assert!(m.has_key(CONFIG_DB, "VXLAN_TUNNEL_MAP|vtep1|map_10010_Vlan10"));
        assert!(m.has_key(CONFIG_DB, "VXLAN_TUNNEL_MAP|vtep1|map_10020_Vlan20"));
        // Shrinking the set removes the stale row; remapping a VLAN moves it.
        put_maps(&mut m, &MapsInput { maps: vec![MapEntry { vlan_id: 10, vni: 99 }] }).unwrap();
        assert!(m.has_key(CONFIG_DB, "VXLAN_TUNNEL_MAP|vtep1|map_99_Vlan10"));
        assert!(!m.has_key(CONFIG_DB, "VXLAN_TUNNEL_MAP|vtep1|map_10010_Vlan10"));
        assert!(!m.has_key(CONFIG_DB, "VXLAN_TUNNEL_MAP|vtep1|map_10020_Vlan20"));
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["vlan_vni_maps"], json!([{ "vlan_id": 10, "vni": 99 }]));
    }

    #[test]
    fn maps_validation() {
        let mut m = platform();
        // No VTEP yet → conflict, not a write.
        assert!(matches!(
            put_maps(&mut m, &MapsInput { maps: vec![MapEntry { vlan_id: 10, vni: 1 }] })
                .unwrap_err(),
            WriteError::Conflict(_)
        ));
        put_vtep(&mut m, &vtep()).unwrap();
        for maps in [
            vec![MapEntry { vlan_id: 99, vni: 1 }],                                       // no such VLAN
            vec![MapEntry { vlan_id: 0, vni: 1 }],                                        // bad VLAN id
            vec![MapEntry { vlan_id: 10, vni: 0 }],                                       // bad VNI
            vec![MapEntry { vlan_id: 10, vni: 16_777_216 }],                              // VNI too big
            vec![MapEntry { vlan_id: 10, vni: 1 }, MapEntry { vlan_id: 10, vni: 2 }],     // dup VLAN
            vec![MapEntry { vlan_id: 10, vni: 1 }, MapEntry { vlan_id: 20, vni: 1 }],     // dup VNI
        ] {
            let err = put_maps(&mut m, &MapsInput { maps }).unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{err:?}");
        }
    }

    #[test]
    fn delete_vtep_guarded_by_maps() {
        let mut m = platform();
        assert!(matches!(delete_vtep(&mut m).unwrap_err(), WriteError::NotFound(_)));
        put_vtep(&mut m, &vtep()).unwrap();
        put_maps(&mut m, &MapsInput { maps: vec![MapEntry { vlan_id: 10, vni: 10010 }] }).unwrap();
        assert!(matches!(delete_vtep(&mut m).unwrap_err(), WriteError::Conflict(_)));
        put_maps(&mut m, &MapsInput { maps: vec![] }).unwrap();
        delete_vtep(&mut m).unwrap();
        assert!(!m.has_key(CONFIG_DB, "VXLAN_TUNNEL|vtep1"));
        assert!(!m.has_key(CONFIG_DB, "EVPN_NVO|nvo"));
    }

    #[test]
    fn status_reports_remotes_and_mappings() {
        let mut m = platform();
        put_vtep(&mut m, &vtep()).unwrap();
        put_maps(&mut m, &MapsInput { maps: vec![MapEntry { vlan_id: 10, vni: 10010 }] }).unwrap();
        m.seed(STATE_DB, "VXLAN_TUNNEL_TABLE|vtep1", &[("operstatus", "oper_up")]);
        m.seed(STATE_DB, "VXLAN_TUNNEL_TABLE|EVPN_10.0.0.12", &[("operstatus", "oper_up")]);
        m.seed(STATE_DB, "VXLAN_TUNNEL_TABLE|static0", &[("dst_ip", "10.0.0.13"), ("operstatus", "oper_down")]);
        m.seed(APPL_DB, "VXLAN_REMOTE_VNI_TABLE:Vlan10:10.0.0.12", &[("vni", "10010")]);
        let doc = get_status(&mut m).unwrap();
        assert_eq!(doc["vtep"]["name"], "vtep1");
        let remotes = doc["remote_vteps"].as_array().unwrap();
        assert_eq!(remotes.len(), 2);
        assert_eq!(remotes[0]["ip"], "10.0.0.12");
        assert_eq!(remotes[0]["oper_status"], "up");
        assert_eq!(remotes[0]["source"], "evpn");
        assert_eq!(remotes[0]["vnis"], json!([10010]));
        assert_eq!(remotes[1]["ip"], "10.0.0.13");
        assert_eq!(remotes[1]["oper_status"], "down");
        assert_eq!(remotes[1]["source"], "static");
        assert_eq!(remotes[1]["vnis"], json!([]));
        assert_eq!(doc["mappings"][0]["vlan_id"], 10);
        assert_eq!(doc["mappings"][0]["oper_status"], "up");
    }

    #[test]
    fn map_key_fallback_parsing() {
        let empty = HashMap::new();
        assert_eq!(parse_map("map_10010_Vlan10", &empty), Some((10, 10010)));
        assert_eq!(parse_map("nonsense", &empty), None);
        let fields: HashMap<String, String> =
            [("vlan".to_string(), "Vlan20".to_string()), ("vni".to_string(), "42".to_string())]
                .into_iter()
                .collect();
        assert_eq!(parse_map("whatever", &fields), Some((20, 42)));
    }
}
