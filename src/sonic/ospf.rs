//! OSPFv2 for the console's Configure → Routing → OSPF page.
//!
//! Only the frrcfgd path can manage OSPF from CONFIG_DB (ospfd runs under
//! frr_mgmt_framework on community images; enterprise ships its own OSPF
//! stack on the same tables), so support is gated on the capability probe.
//! frrcfgd.py's field maps are the schema truth — no yang model exists:
//!   OSPFV2_ROUTER|<vrf>                          router_id, distance
//!   OSPFV2_ROUTER_AREA|<vrf>|<area>              stub "true"/"false"
//!   OSPFV2_ROUTER_AREA_NETWORK|<vrf>|<area>|<prefix>   (keyless rows)
//!   OSPFV2_ROUTER_PASSIVE_INTERFACE|<vrf>|<ifname>     (keyless rows)
//!   OSPFV2_INTERFACE|<ifname>|<address>          area-id, cost,
//!       hello-interval, dead-interval, network-type, bfd
//! The OSPFV2_INTERFACE key wants an address; rows we create use 0.0.0.0
//! ("whole interface") and updates reuse whatever address the row already
//! has. Neighbors come from `vtysh -c "show ip ospf vrf all neighbor json"`.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::l3;
use super::probe::{self, Capability};
use super::store::{self, field, keys, row, three_parts, two_parts, Platform};
use super::switching::{check_cidrs, natural_cmp, parse_bool, parse_num, WriteError, WriteResult};
use super::CONFIG_DB;

const UNSUPPORTED: &str = "OSPF requires the FRR management framework \
                           (frr_mgmt_framework_config=true) or Enterprise SONiC";

fn supported(p: &probe::Probe) -> bool {
    p.ospf_supported()
}

// ── GET /api/routing/ospf ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct AreaDoc {
    area_id: String,
    stub: bool,
    networks: Vec<String>,
}

#[derive(Debug, Serialize)]
struct InstanceDoc {
    vrf: String,
    router_id: Option<String>,
    distance: Option<u64>,
    areas: Vec<AreaDoc>,
}

#[derive(Debug, Serialize)]
struct InterfaceDoc {
    name: String,
    area: Option<String>,
    cost: Option<u64>,
    hello_interval: Option<u64>,
    dead_interval: Option<u64>,
    network_type: Option<&'static str>,
    passive: bool,
    bfd: bool,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct NeighborDoc {
    pub neighbor_id: String,
    pub address: String,
    pub interface: String,
    pub state: String,
    pub priority: Option<u64>,
    pub dead_time_secs: Option<u64>,
}

/// Parse `show ip ospf vrf all neighbor json`. FRR nests
/// {vrf: {"neighbors": {rid: [entry, …]}}} (plain {"neighbors": …} without
/// vrfs) and has renamed the entry fields over time — both spellings are
/// accepted. Pure and tolerant.
pub fn parse_ospf_neighbors(text: &str) -> Vec<NeighborDoc> {
    let mut out = Vec::new();
    let Ok(root) = serde_json::from_str::<serde_json::Value>(text) else {
        return out;
    };
    let Some(obj) = root.as_object() else { return out };
    let sections: Vec<&serde_json::Map<String, serde_json::Value>> =
        if obj.contains_key("neighbors") {
            vec![obj]
        } else {
            obj.values().filter_map(|v| v.as_object()).collect()
        };
    for section in sections {
        let Some(neighbors) = section.get("neighbors").and_then(|n| n.as_object()) else {
            continue;
        };
        for (rid, entries) in neighbors {
            let Some(entries) = entries.as_array() else { continue };
            for e in entries {
                let s = |k: &str| e.get(k).and_then(|v| v.as_str()).map(str::to_string);
                let n = |k: &str| e.get(k).and_then(|v| v.as_u64());
                out.push(NeighborDoc {
                    neighbor_id: rid.clone(),
                    address: s("address").or_else(|| s("ifaceAddress")).unwrap_or_default(),
                    interface: s("ifaceName").or_else(|| s("interfaceName")).unwrap_or_default(),
                    state: s("nbrState").or_else(|| s("state")).unwrap_or_default(),
                    priority: n("nbrPriority").or_else(|| n("priority")),
                    dead_time_secs: n("routerDeadIntervalTimerDueMsec")
                        .or_else(|| n("deadTimeMsecs"))
                        .map(|ms| ms / 1000),
                });
            }
        }
    }
    out
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    if !supported(&p) {
        return Ok(json!({
            "capability": Capability::no(UNSUPPORTED),
            "instances": [], "interfaces": [], "neighbors": [],
        }));
    }

    // Areas and their networks, grouped per (vrf, area).
    let mut networks: HashMap<(String, String), Vec<String>> = HashMap::new();
    for key in keys(plat, CONFIG_DB, "OSPFV2_ROUTER_AREA_NETWORK|*") {
        if let Some((vrf, area, prefix)) = three_parts(&key, "OSPFV2_ROUTER_AREA_NETWORK|") {
            networks
                .entry((vrf.to_string(), area.to_string()))
                .or_default()
                .push(prefix.to_string());
        }
    }
    let mut areas: HashMap<String, Vec<AreaDoc>> = HashMap::new();
    for key in keys(plat, CONFIG_DB, "OSPFV2_ROUTER_AREA|*") {
        let Some((vrf, area)) = two_parts(&key, "OSPFV2_ROUTER_AREA|") else { continue };
        let r = row(plat, CONFIG_DB, &key);
        let mut nets = networks
            .remove(&(vrf.to_string(), area.to_string()))
            .unwrap_or_default();
        nets.sort();
        areas.entry(vrf.to_string()).or_default().push(AreaDoc {
            area_id: area.to_string(),
            stub: parse_bool(field(&r, "stub")).unwrap_or(false),
            networks: nets,
        });
    }
    let mut instances = Vec::new();
    for key in plat.scan(CONFIG_DB, "OSPFV2_ROUTER|*")? {
        let Some(vrf) = key.strip_prefix("OSPFV2_ROUTER|") else { continue };
        if vrf.is_empty() || vrf.contains('|') {
            continue;
        }
        let r = row(plat, CONFIG_DB, &key);
        let mut vrf_areas = areas.remove(vrf).unwrap_or_default();
        vrf_areas.sort_by(|a, b| a.area_id.cmp(&b.area_id));
        instances.push(InstanceDoc {
            vrf: vrf.to_string(),
            router_id: field(&r, "router_id").map(str::to_string),
            distance: parse_num(field(&r, "distance")),
            areas: vrf_areas,
        });
    }
    instances.sort_by(|a, b| a.vrf.cmp(&b.vrf));

    // Passive markers, keyed by interface.
    let mut passive: BTreeSet<String> = BTreeSet::new();
    for key in keys(plat, CONFIG_DB, "OSPFV2_ROUTER_PASSIVE_INTERFACE|*") {
        if let Some((_vrf, ifname)) = two_parts(&key, "OSPFV2_ROUTER_PASSIVE_INTERFACE|") {
            passive.insert(ifname.split('|').next().unwrap_or(ifname).to_string());
        }
    }
    // First OSPFV2_INTERFACE row per interface (rows are per-address).
    let mut ospf_rows: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut if_keys = keys(plat, CONFIG_DB, "OSPFV2_INTERFACE|*");
    if_keys.sort();
    for key in if_keys {
        let Some((ifname, _addr)) = two_parts(&key, "OSPFV2_INTERFACE|") else { continue };
        if !ospf_rows.contains_key(ifname) {
            let r = row(plat, CONFIG_DB, &key);
            ospf_rows.insert(ifname.to_string(), r);
        }
    }
    // All L3 interfaces appear; area is null for the ones outside OSPF.
    let l3_doc = l3::get_interfaces(plat)?;
    let mut interfaces = Vec::new();
    if let Some(list) = l3_doc["interfaces"].as_array() {
        for l3_if in list {
            let Some(name) = l3_if["name"].as_str() else { continue };
            let empty = HashMap::new();
            let r = ospf_rows.get(name).unwrap_or(&empty);
            interfaces.push(InterfaceDoc {
                name: name.to_string(),
                area: field(r, "area-id").map(str::to_string),
                cost: parse_num(field(r, "cost")),
                hello_interval: parse_num(field(r, "hello-interval")),
                dead_interval: parse_num(field(r, "dead-interval")),
                network_type: match field(r, "network-type") {
                    Some("broadcast") => Some("broadcast"),
                    Some("point-to-point") => Some("point-to-point"),
                    _ => None,
                },
                passive: passive.contains(name),
                bfd: parse_bool(field(r, "bfd")).unwrap_or(false),
            });
        }
    }
    interfaces.sort_by(|a, b| natural_cmp(&a.name, &b.name));

    let neighbors = plat
        .run("vtysh", &["-c", "show ip ospf vrf all neighbor json"])
        .ok()
        .filter(|o| o.ok)
        .map(|o| parse_ospf_neighbors(&o.stdout))
        .unwrap_or_default();

    Ok(json!({
        "capability": Capability::yes(),
        "instances": instances,
        "interfaces": interfaces,
        "neighbors": neighbors,
    }))
}

// ── writes ──────────────────────────────────────────────────────────────────

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

fn require_supported(plat: &mut dyn Platform) -> WriteResult {
    if !supported(&probe::current(plat)) {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    Ok(())
}

fn check_vrf(plat: &mut dyn Platform, vrf: &str) -> WriteResult {
    if vrf == "default" {
        return Ok(());
    }
    if !vrf.starts_with("Vrf") {
        return Err(bad(format!("invalid vrf {vrf:?} (default or Vrf…)")));
    }
    if !plat.exists(CONFIG_DB, &format!("VRF|{vrf}")).map_err(WriteError::Redis)? {
        return Err(bad(format!("no such VRF {vrf}")));
    }
    Ok(())
}

/// Area ids are dotted-quad or plain u32; normalize to FRR's canonical
/// dotted-quad so keys stay unique.
pub fn normalize_area(area: &str) -> Option<String> {
    if area.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(area.to_string());
    }
    let n: u32 = area.parse().ok()?;
    Some(std::net::Ipv4Addr::from(n).to_string())
}

#[derive(Debug, Deserialize)]
pub struct InstanceInput {
    pub enabled: bool,
    pub router_id: Option<String>,
    pub distance: Option<u64>,
}

pub fn put_instance(plat: &mut dyn Platform, vrf: &str, input: &InstanceInput) -> WriteResult {
    let _lock = store::feature_lock("ospf");
    require_supported(plat)?;
    check_vrf(plat, vrf)?;
    if !input.enabled {
        // Tear down the instance: router row, areas, networks, passive
        // markers. Per-interface OSPFV2_INTERFACE rows are managed through
        // their own endpoint and stay (inert without a router).
        let mut doomed = vec![format!("OSPFV2_ROUTER|{vrf}")];
        for pattern in [
            format!("OSPFV2_ROUTER_AREA|{vrf}|*"),
            format!("OSPFV2_ROUTER_AREA_NETWORK|{vrf}|*"),
            format!("OSPFV2_ROUTER_PASSIVE_INTERFACE|{vrf}|*"),
        ] {
            doomed.extend(plat.scan(CONFIG_DB, &pattern).map_err(WriteError::Redis)?);
        }
        for key in doomed {
            plat.del(CONFIG_DB, &key).map_err(WriteError::Redis)?;
        }
        return Ok(());
    }
    if let Some(rid) = &input.router_id {
        if rid.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(bad(format!("invalid router_id {rid:?}")));
        }
    }
    if let Some(d) = input.distance {
        if !(1..=255).contains(&d) {
            return Err(bad(format!("invalid distance {d} (must be 1-255)")));
        }
    }
    let key = format!("OSPFV2_ROUTER|{vrf}");
    plat.hset(CONFIG_DB, &key, &[("enable", "true")]).map_err(WriteError::Redis)?;
    for (fname, v) in [
        ("router_id", input.router_id.clone()),
        ("distance", input.distance.map(|v| v.to_string())),
    ] {
        match v {
            Some(v) => plat
                .hset(CONFIG_DB, &key, &[(fname, v.as_str())])
                .map_err(WriteError::Redis)?,
            None => plat.hdel(CONFIG_DB, &key, &[fname]).map_err(WriteError::Redis)?,
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct AreaInput {
    #[serde(default)]
    pub stub: bool,
    /// Full desired set of `network` statements for the area.
    #[serde(default)]
    pub networks: Vec<String>,
}

pub fn put_area(
    plat: &mut dyn Platform,
    vrf: &str,
    area: &str,
    input: &AreaInput,
) -> WriteResult {
    let _lock = store::feature_lock("ospf");
    require_supported(plat)?;
    check_vrf(plat, vrf)?;
    let Some(area) = normalize_area(area) else {
        return Err(bad(format!("invalid area id {area:?} (dotted quad or number)")));
    };
    check_cidrs(&input.networks).map_err(bad)?;
    if !plat.exists(CONFIG_DB, &format!("OSPFV2_ROUTER|{vrf}")).map_err(WriteError::Redis)? {
        return Err(bad(format!("no OSPF instance for vrf {vrf} (enable it first)")));
    }
    let prefix = format!("OSPFV2_ROUTER_AREA_NETWORK|{vrf}|{area}|");
    let current: Vec<String> = plat
        .scan(CONFIG_DB, &format!("{prefix}*"))
        .map_err(WriteError::Redis)?;
    let desired: BTreeSet<&str> = input.networks.iter().map(String::as_str).collect();
    store::apply(plat, |b| {
        b.hset(
            CONFIG_DB,
            &format!("OSPFV2_ROUTER_AREA|{vrf}|{area}"),
            &[("stub", if input.stub { "true" } else { "false" })],
        )?;
        // Converge the network rows to the full desired set.
        for key in &current {
            let Some(prefix_net) = key.strip_prefix(&prefix) else { continue };
            if !desired.contains(prefix_net) {
                b.del(CONFIG_DB, key)?;
            }
        }
        for net in &desired {
            b.hset(CONFIG_DB, &format!("{prefix}{net}"), &[("NULL", "NULL")])?;
        }
        Ok(())
    })
    .map_err(WriteError::Redis)
}

pub fn delete_area(plat: &mut dyn Platform, vrf: &str, area: &str) -> WriteResult {
    let _lock = store::feature_lock("ospf");
    require_supported(plat)?;
    let Some(area) = normalize_area(area) else {
        return Err(bad(format!("invalid area id {area:?}")));
    };
    let key = format!("OSPFV2_ROUTER_AREA|{vrf}|{area}");
    if !plat.exists(CONFIG_DB, &key).map_err(WriteError::Redis)? {
        return Err(WriteError::NotFound(format!("no such area {area} in vrf {vrf}")));
    }
    for net in plat
        .scan(CONFIG_DB, &format!("OSPFV2_ROUTER_AREA_NETWORK|{vrf}|{area}|*"))
        .map_err(WriteError::Redis)?
    {
        plat.del(CONFIG_DB, &net).map_err(WriteError::Redis)?;
    }
    plat.del(CONFIG_DB, &key).map_err(WriteError::Redis)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum NetworkType {
    #[serde(rename = "broadcast")]
    Broadcast,
    #[serde(rename = "point-to-point")]
    PointToPoint,
}

#[derive(Debug, Deserialize)]
pub struct OspfInterfaceInput {
    /// null removes the interface from OSPF.
    pub area: Option<String>,
    pub cost: Option<u64>,
    pub hello_interval: Option<u64>,
    pub dead_interval: Option<u64>,
    pub network_type: Option<NetworkType>,
    #[serde(default)]
    pub passive: bool,
    #[serde(default)]
    pub bfd: bool,
}

pub fn put_interface(
    plat: &mut dyn Platform,
    name: &str,
    input: &OspfInterfaceInput,
) -> WriteResult {
    let _lock = store::feature_lock("ospf");
    require_supported(plat)?;
    // The interface must be a real L3-capable one.
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
    // The passive marker rows live under the interface's VRF.
    let vrf = field(
        &row(plat, CONFIG_DB, &format!("{}|{}", l3::l3_table(name), name)),
        "vrf_name",
    )
    .unwrap_or("default")
    .to_string();
    let existing_rows = plat
        .scan(CONFIG_DB, &format!("OSPFV2_INTERFACE|{name}|*"))
        .map_err(WriteError::Redis)?;

    let Some(area) = &input.area else {
        // area null → out of OSPF entirely.
        for key in existing_rows {
            plat.del(CONFIG_DB, &key).map_err(WriteError::Redis)?;
        }
        plat.del(CONFIG_DB, &format!("OSPFV2_ROUTER_PASSIVE_INTERFACE|{vrf}|{name}"))
            .map_err(WriteError::Redis)?;
        return Ok(());
    };
    let Some(area) = normalize_area(area) else {
        return Err(bad(format!("invalid area id {area:?} (dotted quad or number)")));
    };
    for (fname, v, lo, hi) in [
        ("cost", input.cost, 1, 65_535),
        ("hello_interval", input.hello_interval, 1, 65_535),
        ("dead_interval", input.dead_interval, 1, 65_535),
    ] {
        if let Some(v) = v {
            if !(lo..=hi).contains(&v) {
                return Err(bad(format!("invalid {fname} {v} (must be {lo}-{hi})")));
            }
        }
    }

    // Reuse the address the row already carries; new rows bind 0.0.0.0
    // (the whole interface).
    let key = existing_rows
        .first()
        .cloned()
        .unwrap_or_else(|| format!("OSPFV2_INTERFACE|{name}|0.0.0.0"));
    store::apply(plat, |b| {
        b.hset(
            CONFIG_DB,
            &key,
            &[
                ("area-id", area.as_str()),
                ("bfd", if input.bfd { "true" } else { "false" }),
            ],
        )?;
        for (fname, v) in [
            ("cost", input.cost.map(|v| v.to_string())),
            ("hello-interval", input.hello_interval.map(|v| v.to_string())),
            ("dead-interval", input.dead_interval.map(|v| v.to_string())),
            (
                "network-type",
                input.network_type.map(|t| {
                    match t {
                        NetworkType::Broadcast => "broadcast",
                        NetworkType::PointToPoint => "point-to-point",
                    }
                    .to_string()
                }),
            ),
        ] {
            match v {
                Some(v) => b.hset(CONFIG_DB, &key, &[(fname, v.as_str())])?,
                None => b.hdel(CONFIG_DB, &key, &[fname])?,
            }
        }
        let passive_key = format!("OSPFV2_ROUTER_PASSIVE_INTERFACE|{vrf}|{name}");
        if input.passive {
            b.hset(CONFIG_DB, &passive_key, &[("NULL", "NULL")])?;
        } else {
            b.del(CONFIG_DB, &passive_key)?;
        }
        Ok(())
    })
    .map_err(WriteError::Redis)
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::super::store::CmdOutput;
    use super::*;

    fn frr() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202505.1'\n");
        m.seed(CONFIG_DB, "FEATURE|bgp", &[("state", "enabled")]);
        m.seed(
            CONFIG_DB,
            "DEVICE_METADATA|localhost",
            &[("frr_mgmt_framework_config", "true")],
        );
        m.seed(CONFIG_DB, "PORT|Ethernet0", &[("admin_status", "up")]);
        m.seed(CONFIG_DB, "PORT|Ethernet4", &[("admin_status", "up")]);
        m
    }

    #[test]
    fn unsupported_without_frrcfgd() {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        m.seed(CONFIG_DB, "FEATURE|bgp", &[("state", "enabled")]);
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        let err = put_instance(
            &mut m,
            "default",
            &InstanceInput { enabled: true, router_id: None, distance: None },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
        assert!(!m.has_key(CONFIG_DB, "OSPFV2_ROUTER|default"));
    }

    #[test]
    fn area_networks_converge_as_full_set() {
        let mut m = frr();
        m.seed(CONFIG_DB, "OSPFV2_ROUTER|default", &[("enable", "true")]);
        m.seed(CONFIG_DB, "OSPFV2_ROUTER_AREA|default|0.0.0.0", &[("stub", "false")]);
        m.seed(
            CONFIG_DB,
            "OSPFV2_ROUTER_AREA_NETWORK|default|0.0.0.0|10.0.0.0/24",
            &[("NULL", "NULL")],
        );
        m.seed(
            CONFIG_DB,
            "OSPFV2_ROUTER_AREA_NETWORK|default|0.0.0.0|10.0.1.0/24",
            &[("NULL", "NULL")],
        );
        put_area(
            &mut m,
            "default",
            "0", // numeric area normalizes to 0.0.0.0
            &AreaInput {
                stub: true,
                networks: vec!["10.0.0.0/24".into(), "10.0.2.0/24".into()],
            },
        )
        .unwrap();
        assert_eq!(
            m.row(CONFIG_DB, "OSPFV2_ROUTER_AREA|default|0.0.0.0").get("stub").unwrap(),
            "true"
        );
        assert!(m.has_key(CONFIG_DB, "OSPFV2_ROUTER_AREA_NETWORK|default|0.0.0.0|10.0.0.0/24"));
        assert!(m.has_key(CONFIG_DB, "OSPFV2_ROUTER_AREA_NETWORK|default|0.0.0.0|10.0.2.0/24"));
        assert!(!m.has_key(CONFIG_DB, "OSPFV2_ROUTER_AREA_NETWORK|default|0.0.0.0|10.0.1.0/24"));
    }

    #[test]
    fn interface_put_and_removal() {
        let mut m = frr();
        put_interface(
            &mut m,
            "Ethernet0",
            &OspfInterfaceInput {
                area: Some("0.0.0.0".into()),
                cost: Some(10),
                hello_interval: Some(5),
                dead_interval: Some(20),
                network_type: Some(NetworkType::PointToPoint),
                passive: true,
                bfd: true,
            },
        )
        .unwrap();
        let row = m.row(CONFIG_DB, "OSPFV2_INTERFACE|Ethernet0|0.0.0.0");
        assert_eq!(row.get("area-id").unwrap(), "0.0.0.0");
        assert_eq!(row.get("cost").unwrap(), "10");
        assert_eq!(row.get("network-type").unwrap(), "point-to-point");
        assert_eq!(row.get("bfd").unwrap(), "true");
        assert!(m.has_key(CONFIG_DB, "OSPFV2_ROUTER_PASSIVE_INTERFACE|default|Ethernet0"));
        // area null pulls the interface out of OSPF.
        put_interface(
            &mut m,
            "Ethernet0",
            &OspfInterfaceInput {
                area: None,
                cost: None,
                hello_interval: None,
                dead_interval: None,
                network_type: None,
                passive: false,
                bfd: false,
            },
        )
        .unwrap();
        assert!(!m.has_key(CONFIG_DB, "OSPFV2_INTERFACE|Ethernet0|0.0.0.0"));
        assert!(!m.has_key(CONFIG_DB, "OSPFV2_ROUTER_PASSIVE_INTERFACE|default|Ethernet0"));
    }

    #[test]
    fn get_assembles_instances_interfaces_and_neighbors() {
        let mut m = frr();
        m.seed(
            CONFIG_DB,
            "OSPFV2_ROUTER|default",
            &[("router_id", "1.1.1.1"), ("distance", "110")],
        );
        m.seed(CONFIG_DB, "OSPFV2_ROUTER_AREA|default|0.0.0.0", &[("stub", "false")]);
        m.seed(
            CONFIG_DB,
            "OSPFV2_ROUTER_AREA_NETWORK|default|0.0.0.0|10.0.0.0/24",
            &[("NULL", "NULL")],
        );
        m.seed(
            CONFIG_DB,
            "OSPFV2_INTERFACE|Ethernet0|0.0.0.0",
            &[("area-id", "0.0.0.0"), ("cost", "10")],
        );
        m.seed(CONFIG_DB, "OSPFV2_ROUTER_PASSIVE_INTERFACE|default|Ethernet4", &[("NULL", "NULL")]);
        m.on_cmd(
            &["vtysh", "-c", "show ip ospf vrf all neighbor json"],
            CmdOutput {
                ok: true,
                stdout: r#"{"default":{"neighbors":{"2.2.2.2":[{"address":"10.0.0.2","ifaceName":"Ethernet0:10.0.0.1","nbrState":"Full/DR","nbrPriority":1,"routerDeadIntervalTimerDueMsec":35000}]}}}"#.to_string(),
                stderr: String::new(),
            },
        );
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["instances"][0]["vrf"], "default");
        assert_eq!(doc["instances"][0]["router_id"], "1.1.1.1");
        assert_eq!(doc["instances"][0]["areas"][0]["networks"], json!(["10.0.0.0/24"]));
        let ifs = doc["interfaces"].as_array().unwrap();
        let e0 = ifs.iter().find(|i| i["name"] == "Ethernet0").unwrap();
        assert_eq!(e0["area"], "0.0.0.0");
        assert_eq!(e0["cost"], 10);
        let e4 = ifs.iter().find(|i| i["name"] == "Ethernet4").unwrap();
        assert_eq!(e4["area"], serde_json::Value::Null);
        assert_eq!(e4["passive"], true);
        let n = &doc["neighbors"][0];
        assert_eq!(n["neighbor_id"], "2.2.2.2");
        assert_eq!(n["state"], "Full/DR");
        assert_eq!(n["dead_time_secs"], 35);
    }

    #[test]
    fn instance_teardown_and_validation() {
        let mut m = frr();
        m.seed(CONFIG_DB, "OSPFV2_ROUTER|default", &[("enable", "true")]);
        m.seed(CONFIG_DB, "OSPFV2_ROUTER_AREA|default|0.0.0.0", &[("stub", "false")]);
        m.seed(
            CONFIG_DB,
            "OSPFV2_ROUTER_AREA_NETWORK|default|0.0.0.0|10.0.0.0/24",
            &[("NULL", "NULL")],
        );
        put_instance(
            &mut m,
            "default",
            &InstanceInput { enabled: false, router_id: None, distance: None },
        )
        .unwrap();
        assert!(!m.has_key(CONFIG_DB, "OSPFV2_ROUTER|default"));
        assert!(!m.has_key(CONFIG_DB, "OSPFV2_ROUTER_AREA|default|0.0.0.0"));
        assert!(!m.has_key(CONFIG_DB, "OSPFV2_ROUTER_AREA_NETWORK|default|0.0.0.0|10.0.0.0/24"));
        // Bad router id / distance → 400.
        let err = put_instance(
            &mut m,
            "default",
            &InstanceInput { enabled: true, router_id: Some("nope".into()), distance: None },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
        let err = put_instance(
            &mut m,
            "default",
            &InstanceInput { enabled: true, router_id: None, distance: Some(0) },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
    }

    #[test]
    fn area_ids_normalize() {
        assert_eq!(normalize_area("0").as_deref(), Some("0.0.0.0"));
        assert_eq!(normalize_area("0.0.0.10").as_deref(), Some("0.0.0.10"));
        assert_eq!(normalize_area("256").as_deref(), Some("0.0.1.0"));
        assert_eq!(normalize_area("bogus"), None);
    }
}
