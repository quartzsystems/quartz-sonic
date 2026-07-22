//! L3 interfaces and VRFs for the console's Configure → Routing → L3
//! Interfaces / VRFs pages. CONFIG_DB-native on every SONiC flavor, so the
//! capability envelope is always supported.
//!
//! The four interface tables share one shape: an attribute-level key
//! `<TABLE>|<name>` (vrf_name lives here; an otherwise-empty row needs the
//! {"NULL":"NULL"} placeholder so intfmgrd picks up the per-address children)
//! and IP-level keys `<TABLE>|<name>|<prefix>` (v4 and v6, no fields).
//! Tables: INTERFACE (ports), PORTCHANNEL_INTERFACE, VLAN_INTERFACE,
//! LOOPBACK_INTERFACE.
//!
//! VRF rebinding is sequenced the way SONiC demands — it refuses a vrf_name
//! change while addresses exist — so a PUT that moves an interface removes
//! all its IP rows, flips vrf_name on the attribute row, then re-adds the
//! desired set (rolled back together on a mid-batch redis failure).

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::Capability;
use super::store::{self, field, key_suffix, keys, row, two_parts, Platform};
use super::switching::{check_cidrs, natural_cmp, parse_bool, parse_num, WriteError, WriteResult};
use super::{APPL_DB, CONFIG_DB};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Port,
    PortChannel,
    Vlan,
    Loopback,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Port => "port",
            Kind::PortChannel => "port-channel",
            Kind::Vlan => "vlan",
            Kind::Loopback => "loopback",
        }
    }
}

pub fn kind_of(name: &str) -> Kind {
    if name.starts_with("PortChannel") {
        Kind::PortChannel
    } else if name.starts_with("Vlan") {
        Kind::Vlan
    } else if name.starts_with("Loopback") {
        Kind::Loopback
    } else {
        Kind::Port
    }
}

/// The CONFIG_DB interface table an interface's L3 rows live in.
pub fn l3_table(name: &str) -> &'static str {
    match kind_of(name) {
        Kind::Port => "INTERFACE",
        Kind::PortChannel => "PORTCHANNEL_INTERFACE",
        Kind::Vlan => "VLAN_INTERFACE",
        Kind::Loopback => "LOOPBACK_INTERFACE",
    }
}

const ALL_TABLES: [&str; 4] =
    ["INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_INTERFACE", "LOOPBACK_INTERFACE"];

/// (attribute rows by interface, IP lists by interface) across all four
/// interface tables.
fn l3_rows(
    plat: &mut dyn Platform,
) -> anyhow::Result<(HashMap<String, HashMap<String, String>>, HashMap<String, Vec<String>>)> {
    let mut attrs: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut ips: HashMap<String, Vec<String>> = HashMap::new();
    for table in ALL_TABLES {
        let prefix = format!("{table}|");
        for key in plat.scan(CONFIG_DB, &format!("{table}|*"))? {
            if let Some((name, cidr)) = two_parts(&key, &prefix) {
                ips.entry(name.to_string()).or_default().push(cidr.to_string());
            } else if let Some(name) = key_suffix(&key, &prefix) {
                let r = row(plat, CONFIG_DB, &key);
                attrs.insert(name.to_string(), r);
            }
        }
    }
    for list in ips.values_mut() {
        list.sort();
    }
    Ok((attrs, ips))
}

#[derive(Debug, Serialize)]
struct InterfaceDoc {
    name: String,
    kind: &'static str,
    vrf: Option<String>,
    ip_addresses: Vec<String>,
    admin_status: String,
    oper_status: String,
    description: Option<String>,
}

pub fn get_interfaces(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    // Every L3-capable interface appears: all front-panel ports,
    // port-channels, VLANs (SVI configured or not), and loopbacks.
    let mut names: Vec<String> = Vec::new();
    for (table, prefix) in [("PORT|*", "PORT|"), ("PORTCHANNEL|*", "PORTCHANNEL|"), ("VLAN|*", "VLAN|")]
    {
        for key in plat.scan(CONFIG_DB, table)? {
            if let Some(name) = key_suffix(&key, prefix) {
                names.push(name.to_string());
            }
        }
    }
    let (attrs, ips) = l3_rows(plat)?;
    for name in attrs.keys().chain(ips.keys()) {
        if kind_of(name) == Kind::Loopback {
            names.push(name.clone());
        }
    }
    names.sort_by(|a, b| natural_cmp(a, b));
    names.dedup();

    let mut interfaces = Vec::with_capacity(names.len());
    for name in names {
        let kind = kind_of(&name);
        let cfg = match kind {
            Kind::Port => row(plat, CONFIG_DB, &format!("PORT|{name}")),
            Kind::PortChannel => row(plat, CONFIG_DB, &format!("PORTCHANNEL|{name}")),
            Kind::Vlan => row(plat, CONFIG_DB, &format!("VLAN|{name}")),
            Kind::Loopback => HashMap::new(),
        };
        let oper = match kind {
            Kind::Port => oper_of(&row(plat, APPL_DB, &format!("PORT_TABLE:{name}"))),
            Kind::PortChannel => oper_of(&row(plat, APPL_DB, &format!("LAG_TABLE:{name}"))),
            Kind::Vlan => oper_of(&row(plat, APPL_DB, &format!("VLAN_TABLE:{name}"))),
            Kind::Loopback => "up".to_string(),
        };
        let admin = match kind {
            Kind::Port | Kind::PortChannel => {
                field(&cfg, "admin_status").unwrap_or("down").to_string()
            }
            // SVIs and loopbacks have no admin knob in CONFIG_DB.
            Kind::Vlan | Kind::Loopback => "up".to_string(),
        };
        let attr = attrs.get(&name);
        interfaces.push(InterfaceDoc {
            kind: kind.as_str(),
            vrf: attr.and_then(|a| field(a, "vrf_name")).map(str::to_string),
            ip_addresses: ips.get(&name).cloned().unwrap_or_default(),
            admin_status: admin,
            oper_status: oper,
            description: field(&cfg, "description").map(str::to_string),
            name,
        });
    }
    Ok(json!({ "capability": Capability::yes(), "interfaces": interfaces }))
}

fn oper_of(appl: &HashMap<String, String>) -> String {
    field(appl, "oper_status").unwrap_or("unknown").to_string()
}

// ── PUT /api/routing/l3-interfaces/{name} ───────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct InterfaceInput {
    pub vrf: Option<String>,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
}

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

fn base_exists(plat: &mut dyn Platform, name: &str) -> std::result::Result<bool, WriteError> {
    let ok = match kind_of(name) {
        Kind::Port => plat.exists(CONFIG_DB, &format!("PORT|{name}")),
        Kind::PortChannel => plat.exists(CONFIG_DB, &format!("PORTCHANNEL|{name}")),
        Kind::Vlan => plat.exists(CONFIG_DB, &format!("VLAN|{name}")),
        // A loopback exists iff it has LOOPBACK_INTERFACE rows.
        Kind::Loopback => {
            return Ok(!keys(plat, CONFIG_DB, &format!("LOOPBACK_INTERFACE|{name}"))
                .is_empty()
                || !keys(plat, CONFIG_DB, &format!("LOOPBACK_INTERFACE|{name}|*")).is_empty())
        }
    };
    ok.map_err(WriteError::Redis)
}

fn check_input(plat: &mut dyn Platform, input: &InterfaceInput) -> WriteResult {
    if let Some(vrf) = &input.vrf {
        if !vrf.starts_with("Vrf") {
            return Err(bad(format!(
                "invalid VRF {vrf:?} (data VRFs are named Vrf…; the management VRF cannot bind \
                 front-panel interfaces)"
            )));
        }
        if !plat.exists(CONFIG_DB, &format!("VRF|{vrf}")).map_err(WriteError::Redis)? {
            return Err(bad(format!("no such VRF {vrf}")));
        }
    }
    check_cidrs(&input.ip_addresses).map_err(bad)?;
    let mut seen = BTreeSet::new();
    for a in &input.ip_addresses {
        if !seen.insert(a) {
            return Err(bad(format!("duplicate address {a}")));
        }
    }
    Ok(())
}

/// Converge one interface's attribute row and IP rows. `ip_addresses` is the
/// full desired set.
pub fn put_interface(plat: &mut dyn Platform, name: &str, input: &InterfaceInput) -> WriteResult {
    let _lock = store::feature_lock("l3");
    if !base_exists(plat, name)? {
        let hint = if kind_of(name) == Kind::Loopback {
            " (create loopbacks with POST /api/routing/l3-interfaces)"
        } else {
            ""
        };
        return Err(WriteError::NotFound(format!("no such interface {name}{hint}")));
    }
    check_input(plat, input)?;
    converge(plat, name, input).map_err(WriteError::Redis)
}

/// The shared attribute/IP convergence (assumes validation already ran).
fn converge(plat: &mut dyn Platform, name: &str, input: &InterfaceInput) -> anyhow::Result<()> {
    let table = l3_table(name);
    let attr_key = format!("{table}|{name}");
    let cur_attr = plat.hgetall(CONFIG_DB, &attr_key)?;
    let cur_vrf = field(&cur_attr, "vrf_name").map(str::to_string);
    let prefix = format!("{table}|{name}|");
    let cur_ips: Vec<String> = plat
        .scan(CONFIG_DB, &format!("{table}|{name}|*"))?
        .iter()
        .filter_map(|k| key_suffix(k, &prefix))
        .map(str::to_string)
        .collect();
    let desired: BTreeSet<&str> = input.ip_addresses.iter().map(String::as_str).collect();
    let vrf_changed = cur_vrf.as_deref() != input.vrf.as_deref();

    store::apply(plat, |b| {
        // 1. Remove IP rows: all of them on a VRF change (SONiC refuses
        //    rebinding while addresses exist), otherwise just the stale ones.
        for ip in &cur_ips {
            if vrf_changed || !desired.contains(ip.as_str()) {
                b.del(CONFIG_DB, &format!("{table}|{name}|{ip}"))?;
            }
        }
        // 2. Converge the attribute row (before any IP row exists again).
        match &input.vrf {
            Some(vrf) => {
                b.hset(CONFIG_DB, &attr_key, &[("vrf_name", vrf)])?;
                b.hdel(CONFIG_DB, &attr_key, &["NULL"])?;
            }
            None if !desired.is_empty() => {
                b.hdel(CONFIG_DB, &attr_key, &["vrf_name"])?;
                b.hset(CONFIG_DB, &attr_key, &[("NULL", "NULL")])?;
            }
            None => b.del(CONFIG_DB, &attr_key)?,
        }
        // 3. (Re-)add IP rows.
        for ip in &desired {
            if vrf_changed || !cur_ips.iter().any(|c| c == ip) {
                b.hset(CONFIG_DB, &format!("{table}|{name}|{ip}"), &[("NULL", "NULL")])?;
            }
        }
        Ok(())
    })
}

// ── POST / DELETE /api/routing/l3-interfaces ────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoopbackCreate {
    pub name: String,
    #[serde(flatten)]
    pub input: InterfaceInput,
}

pub fn valid_loopback_name(name: &str) -> bool {
    name.strip_prefix("Loopback")
        .map(|d| !d.is_empty() && d.len() <= 4 && d.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false)
}

pub fn create_loopback(plat: &mut dyn Platform, create: &LoopbackCreate) -> WriteResult {
    let _lock = store::feature_lock("l3");
    if !valid_loopback_name(&create.name) {
        return Err(bad(format!(
            "invalid loopback name {:?} (expected Loopback<0-9999>)",
            create.name
        )));
    }
    if base_exists(plat, &create.name)? {
        return Err(bad(format!("{} already exists", create.name)));
    }
    check_input(plat, &create.input)?;
    converge(plat, &create.name, &create.input).map_err(WriteError::Redis)
}

pub fn delete_interface(plat: &mut dyn Platform, name: &str) -> WriteResult {
    let _lock = store::feature_lock("l3");
    if kind_of(name) != Kind::Loopback {
        return Err(bad(format!(
            "only loopbacks can be deleted; clear {name} with PUT (vrf null, no addresses) instead"
        )));
    }
    if !base_exists(plat, name)? {
        return Err(WriteError::NotFound(format!("no such loopback {name}")));
    }
    for key in plat
        .scan(CONFIG_DB, &format!("LOOPBACK_INTERFACE|{name}|*"))
        .map_err(WriteError::Redis)?
    {
        plat.del(CONFIG_DB, &key).map_err(WriteError::Redis)?;
    }
    plat.del(CONFIG_DB, &format!("LOOPBACK_INTERFACE|{name}")).map_err(WriteError::Redis)?;
    Ok(())
}

// ── VRFs ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct VrfDoc {
    name: String,
    fallback: bool,
    vni: Option<u64>,
    interfaces: Vec<String>,
}

pub fn get_vrfs(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let mut vrfs = Vec::new();
    let (attrs, _) = l3_rows(plat)?;
    for key in plat.scan(CONFIG_DB, "VRF|*")? {
        let Some(name) = key_suffix(&key, "VRF|") else { continue };
        let r = row(plat, CONFIG_DB, &key);
        let mut interfaces: Vec<String> = attrs
            .iter()
            .filter(|(_, a)| field(a, "vrf_name") == Some(name))
            .map(|(ifname, _)| ifname.clone())
            .collect();
        interfaces.sort_by(|a, b| natural_cmp(a, b));
        vrfs.push(VrfDoc {
            name: name.to_string(),
            fallback: parse_bool(field(&r, "fallback")).unwrap_or(false),
            vni: parse_num(field(&r, "vni")),
            interfaces,
        });
    }
    vrfs.sort_by(|a, b| natural_cmp(&a.name, &b.name));
    // mgmtVrfEnabled really is camelCase in CONFIG_DB.
    let mgmt = field(&row(plat, CONFIG_DB, "MGMT_VRF_CONFIG|vrf_global"), "mgmtVrfEnabled")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    Ok(json!({
        "capability": Capability::yes(),
        "vrfs": vrfs,
        "mgmt_vrf_enabled": mgmt,
    }))
}

#[derive(Debug, Deserialize)]
pub struct VrfCreate {
    pub name: String,
    #[serde(default)]
    pub fallback: bool,
    pub vni: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct VrfInput {
    #[serde(default)]
    pub fallback: bool,
    pub vni: Option<u64>,
}

/// SONiC data-VRF names: "Vrf" + more, and short enough for a kernel netdev
/// name (15 chars).
pub fn valid_vrf_name(name: &str) -> bool {
    name.len() > 3
        && name.len() <= 15
        && name.starts_with("Vrf")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn check_vni(vni: Option<u64>) -> std::result::Result<(), String> {
    match vni {
        Some(v) if !(1..=16_777_215).contains(&v) => {
            Err(format!("invalid vni {v} (must be 1-16777215)"))
        }
        _ => Ok(()),
    }
}

pub fn create_vrf(plat: &mut dyn Platform, create: &VrfCreate) -> WriteResult {
    let _lock = store::feature_lock("l3");
    if !valid_vrf_name(&create.name) {
        return Err(bad(format!(
            "invalid VRF name {:?} (must match Vrf<alnum>, at most 15 characters)",
            create.name
        )));
    }
    check_vni(create.vni).map_err(bad)?;
    let key = format!("VRF|{}", create.name);
    if plat.exists(CONFIG_DB, &key).map_err(WriteError::Redis)? {
        return Err(bad(format!("{} already exists", create.name)));
    }
    write_vrf_fields(plat, &key, create.fallback, create.vni)
}

pub fn update_vrf(plat: &mut dyn Platform, name: &str, input: &VrfInput) -> WriteResult {
    let _lock = store::feature_lock("l3");
    check_vni(input.vni).map_err(bad)?;
    let key = format!("VRF|{name}");
    if !plat.exists(CONFIG_DB, &key).map_err(WriteError::Redis)? {
        return Err(WriteError::NotFound(format!("no such VRF {name}")));
    }
    write_vrf_fields(plat, &key, input.fallback, input.vni)
}

fn write_vrf_fields(
    plat: &mut dyn Platform,
    key: &str,
    fallback: bool,
    vni: Option<u64>,
) -> WriteResult {
    plat.hset(CONFIG_DB, key, &[("fallback", if fallback { "true" } else { "false" })])
        .map_err(WriteError::Redis)?;
    match vni {
        Some(v) => plat
            .hset(CONFIG_DB, key, &[("vni", &v.to_string())])
            .map_err(WriteError::Redis)?,
        None => plat.hdel(CONFIG_DB, key, &["vni"]).map_err(WriteError::Redis)?,
    }
    Ok(())
}

pub fn delete_vrf(plat: &mut dyn Platform, name: &str) -> WriteResult {
    let _lock = store::feature_lock("l3");
    if !plat.exists(CONFIG_DB, &format!("VRF|{name}")).map_err(WriteError::Redis)? {
        return Err(WriteError::NotFound(format!("no such VRF {name}")));
    }
    let (attrs, _) = l3_rows(plat).map_err(WriteError::Redis)?;
    let mut bound: Vec<String> = attrs
        .iter()
        .filter(|(_, a)| field(a, "vrf_name") == Some(name))
        .map(|(ifname, _)| ifname.clone())
        .collect();
    if !bound.is_empty() {
        bound.sort_by(|a, b| natural_cmp(a, b));
        return Err(WriteError::Conflict(format!(
            "VRF {name} still has bound interfaces: {}",
            bound.join(", ")
        )));
    }
    plat.del(CONFIG_DB, &format!("VRF|{name}")).map_err(WriteError::Redis)
}

#[derive(Debug, Deserialize)]
pub struct MgmtVrfInput {
    pub enabled: bool,
}

/// PUT /api/routing/vrfs/mgmt — toggling the management VRF restarts the
/// management services, so it goes through `config vrf add|del mgmt`
/// (detached: a synchronous wait would hang on the very services being
/// bounced), never a raw MGMT_VRF_CONFIG write.
pub fn put_mgmt_vrf(plat: &mut dyn Platform, input: &MgmtVrfInput) -> WriteResult {
    let _lock = store::feature_lock("l3");
    let current = field(&row(plat, CONFIG_DB, "MGMT_VRF_CONFIG|vrf_global"), "mgmtVrfEnabled")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if current == input.enabled {
        return Ok(());
    }
    let action = if input.enabled { "add" } else { "del" };
    plat.spawn("config", &["vrf", action, "mgmt"])
        .map_err(|e| WriteError::Internal(format!("config vrf {action} mgmt: {e:#}")))
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::*;

    fn platform() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed(CONFIG_DB, "PORT|Ethernet0", &[("admin_status", "up"), ("description", "uplink")]);
        m.seed(CONFIG_DB, "PORT|Ethernet4", &[("admin_status", "down")]);
        m.seed(CONFIG_DB, "PORTCHANNEL|PortChannel1", &[("admin_status", "up")]);
        m.seed(CONFIG_DB, "VLAN|Vlan10", &[("vlanid", "10")]);
        m.seed(CONFIG_DB, "VRF|VrfBlue", &[("fallback", "false")]);
        m.seed(CONFIG_DB, "VRF|VrfRed", &[("fallback", "true"), ("vni", "1000")]);
        m
    }

    #[test]
    fn interfaces_enumerate_all_kinds() {
        let mut m = platform();
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0", &[("vrf_name", "VrfBlue")]);
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0|10.0.0.1/31", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0|fd00::1/127", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "VLAN_INTERFACE|Vlan10", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "VLAN_INTERFACE|Vlan10|192.168.10.1/24", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "LOOPBACK_INTERFACE|Loopback0|10.1.1.1/32", &[("NULL", "NULL")]);
        m.seed(APPL_DB, "PORT_TABLE:Ethernet0", &[("oper_status", "up")]);
        let doc = get_interfaces(&mut m).unwrap();
        let ifs = doc["interfaces"].as_array().unwrap();
        let by_name = |n: &str| ifs.iter().find(|i| i["name"] == n).unwrap();
        let e0 = by_name("Ethernet0");
        assert_eq!(e0["kind"], "port");
        assert_eq!(e0["vrf"], "VrfBlue");
        assert_eq!(e0["ip_addresses"], json!(["10.0.0.1/31", "fd00::1/127"]));
        assert_eq!(e0["oper_status"], "up");
        assert_eq!(e0["description"], "uplink");
        // A port with no L3 rows still appears, routed-bare.
        let e4 = by_name("Ethernet4");
        assert_eq!(e4["vrf"], serde_json::Value::Null);
        assert_eq!(e4["ip_addresses"], json!([]));
        assert_eq!(by_name("PortChannel1")["kind"], "port-channel");
        assert_eq!(by_name("Vlan10")["kind"], "vlan");
        assert_eq!(by_name("Vlan10")["ip_addresses"], json!(["192.168.10.1/24"]));
        let lo = by_name("Loopback0");
        assert_eq!(lo["kind"], "loopback");
        assert_eq!(lo["oper_status"], "up");
    }

    #[test]
    fn ip_diff_touches_only_changed_rows() {
        let mut m = platform();
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0|10.0.0.1/31", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0|10.0.0.9/31", &[("NULL", "NULL")]);
        put_interface(
            &mut m,
            "Ethernet0",
            &InterfaceInput {
                vrf: None,
                ip_addresses: vec!["10.0.0.1/31".into(), "10.0.0.5/31".into()],
            },
        )
        .unwrap();
        assert!(m.has_key(CONFIG_DB, "INTERFACE|Ethernet0|10.0.0.1/31"));
        assert!(m.has_key(CONFIG_DB, "INTERFACE|Ethernet0|10.0.0.5/31"));
        assert!(!m.has_key(CONFIG_DB, "INTERFACE|Ethernet0|10.0.0.9/31"));
        // The kept address was never deleted or rewritten.
        assert!(
            !m.log.iter().any(|l| l.contains("10.0.0.1/31")),
            "unchanged row was touched: {:?}",
            m.log
        );
    }

    #[test]
    fn vrf_rebind_sequences_ips_around_the_attribute_flip() {
        let mut m = platform();
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0|10.0.0.1/31", &[("NULL", "NULL")]);
        put_interface(
            &mut m,
            "Ethernet0",
            &InterfaceInput {
                vrf: Some("VrfBlue".into()),
                ip_addresses: vec!["10.0.0.1/31".into()],
            },
        )
        .unwrap();
        assert_eq!(
            m.row(CONFIG_DB, "INTERFACE|Ethernet0").get("vrf_name").unwrap(),
            "VrfBlue"
        );
        assert!(m.has_key(CONFIG_DB, "INTERFACE|Ethernet0|10.0.0.1/31"));
        // Sequencing: remove IP → set vrf_name → re-add IP.
        let pos = |needle: &str| {
            m.log
                .iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle} not in {:?}", m.log))
        };
        let del_ip = pos("DEL 4 INTERFACE|Ethernet0|10.0.0.1/31");
        let set_vrf = pos("vrf_name=VrfBlue");
        let add_ip = m
            .log
            .iter()
            .rposition(|l| l.contains("HSET 4 INTERFACE|Ethernet0|10.0.0.1/31"))
            .unwrap();
        assert!(del_ip < set_vrf, "{:?}", m.log);
        assert!(set_vrf < add_ip, "{:?}", m.log);
    }

    #[test]
    fn rebind_failure_rolls_back_written_rows() {
        let mut m = platform();
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0|10.0.0.1/31", &[("NULL", "NULL")]);
        // Fail on the second mutation (the vrf_name HSET), after the IP row
        // was already deleted.
        m.fail_at_write = Some(2);
        let err = put_interface(
            &mut m,
            "Ethernet0",
            &InterfaceInput {
                vrf: Some("VrfBlue".into()),
                ip_addresses: vec!["10.0.0.1/31".into()],
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Redis(_)));
        // The deleted IP row came back; nothing half-applied.
        assert!(m.has_key(CONFIG_DB, "INTERFACE|Ethernet0|10.0.0.1/31"));
        assert!(m.row(CONFIG_DB, "INTERFACE|Ethernet0").get("vrf_name").is_none());
    }

    #[test]
    fn clearing_last_config_removes_attribute_row() {
        let mut m = platform();
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0", &[("vrf_name", "VrfBlue")]);
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0|10.0.0.1/31", &[("NULL", "NULL")]);
        put_interface(&mut m, "Ethernet0", &InterfaceInput { vrf: None, ip_addresses: vec![] })
            .unwrap();
        assert!(!m.has_key(CONFIG_DB, "INTERFACE|Ethernet0"));
        assert!(!m.has_key(CONFIG_DB, "INTERFACE|Ethernet0|10.0.0.1/31"));
    }

    #[test]
    fn interface_input_validation() {
        let mut m = platform();
        // Unknown interface → 404.
        let err = put_interface(
            &mut m,
            "Ethernet99",
            &InterfaceInput { vrf: None, ip_addresses: vec![] },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
        // Unknown or non-Vrf VRF → 400.
        for vrf in ["VrfNope", "mgmt", "default"] {
            let err = put_interface(
                &mut m,
                "Ethernet0",
                &InterfaceInput { vrf: Some(vrf.into()), ip_addresses: vec![] },
            )
            .unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{vrf}");
        }
        // Bad CIDR → 400.
        let err = put_interface(
            &mut m,
            "Ethernet0",
            &InterfaceInput { vrf: None, ip_addresses: vec!["10.0.0.1".into()] },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
    }

    #[test]
    fn loopback_create_and_delete() {
        let mut m = platform();
        create_loopback(
            &mut m,
            &LoopbackCreate {
                name: "Loopback0".into(),
                input: InterfaceInput { vrf: None, ip_addresses: vec!["10.9.9.9/32".into()] },
            },
        )
        .unwrap();
        assert!(m.has_key(CONFIG_DB, "LOOPBACK_INTERFACE|Loopback0"));
        assert!(m.has_key(CONFIG_DB, "LOOPBACK_INTERFACE|Loopback0|10.9.9.9/32"));
        // Duplicate create → 400.
        let err = create_loopback(
            &mut m,
            &LoopbackCreate {
                name: "Loopback0".into(),
                input: InterfaceInput { vrf: None, ip_addresses: vec![] },
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
        // Only loopbacks can be deleted.
        let err = delete_interface(&mut m, "Ethernet0").unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
        delete_interface(&mut m, "Loopback0").unwrap();
        assert!(!m.has_key(CONFIG_DB, "LOOPBACK_INTERFACE|Loopback0"));
        assert!(!m.has_key(CONFIG_DB, "LOOPBACK_INTERFACE|Loopback0|10.9.9.9/32"));
        assert!(!valid_loopback_name("Loopback"));
        assert!(!valid_loopback_name("Loopback1x"));
        assert!(valid_loopback_name("Loopback255"));
    }

    #[test]
    fn vrfs_list_members_and_mgmt_flag() {
        let mut m = platform();
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0", &[("vrf_name", "VrfRed")]);
        m.seed(CONFIG_DB, "VLAN_INTERFACE|Vlan10", &[("vrf_name", "VrfRed")]);
        m.seed(CONFIG_DB, "MGMT_VRF_CONFIG|vrf_global", &[("mgmtVrfEnabled", "true")]);
        let doc = get_vrfs(&mut m).unwrap();
        assert_eq!(doc["mgmt_vrf_enabled"], true);
        let red = doc["vrfs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == "VrfRed")
            .unwrap();
        assert_eq!(red["fallback"], true);
        assert_eq!(red["vni"], 1000);
        assert_eq!(red["interfaces"], json!(["Ethernet0", "Vlan10"]));
    }

    #[test]
    fn vrf_lifecycle_and_guards() {
        let mut m = platform();
        create_vrf(&mut m, &VrfCreate { name: "VrfGreen".into(), fallback: false, vni: Some(42) })
            .unwrap();
        assert_eq!(m.row(CONFIG_DB, "VRF|VrfGreen").get("vni").unwrap(), "42");
        for name in ["green", "Vrf", "VrfWayTooLongForNetdev", "Vrf bad"] {
            let err =
                create_vrf(&mut m, &VrfCreate { name: name.into(), fallback: false, vni: None })
                    .unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{name}");
        }
        // vni clears on update when omitted.
        update_vrf(&mut m, "VrfGreen", &VrfInput { fallback: true, vni: None }).unwrap();
        let row = m.row(CONFIG_DB, "VRF|VrfGreen");
        assert_eq!(row.get("fallback").unwrap(), "true");
        assert!(row.get("vni").is_none());
        // Deleting a VRF with bound interfaces → 409.
        m.seed(CONFIG_DB, "INTERFACE|Ethernet0", &[("vrf_name", "VrfGreen")]);
        let err = delete_vrf(&mut m, "VrfGreen").unwrap_err();
        match err {
            WriteError::Conflict(msg) => assert!(msg.contains("Ethernet0"), "{msg}"),
            other => panic!("expected Conflict, got {other:?}"),
        }
        m.dbs.get_mut(&CONFIG_DB).unwrap().remove("INTERFACE|Ethernet0");
        delete_vrf(&mut m, "VrfGreen").unwrap();
        assert!(!m.has_key(CONFIG_DB, "VRF|VrfGreen"));
    }

    #[test]
    fn mgmt_vrf_toggle_uses_the_cli_detached() {
        let mut m = platform();
        put_mgmt_vrf(&mut m, &MgmtVrfInput { enabled: true }).unwrap();
        assert!(m.log.iter().any(|l| l == "SPAWN config vrf add mgmt"), "{:?}", m.log);
        // Already-enabled → no-op.
        m.seed(CONFIG_DB, "MGMT_VRF_CONFIG|vrf_global", &[("mgmtVrfEnabled", "true")]);
        m.log.clear();
        put_mgmt_vrf(&mut m, &MgmtVrfInput { enabled: true }).unwrap();
        assert!(m.log.is_empty(), "{:?}", m.log);
        put_mgmt_vrf(&mut m, &MgmtVrfInput { enabled: false }).unwrap();
        assert!(m.log.iter().any(|l| l == "SPAWN config vrf del mgmt"), "{:?}", m.log);
    }
}
