//! ACLs for the console's Configure → Security → ACLs page.
//!
//! Backed by CONFIG_DB `ACL_TABLE` / `ACL_RULE` (ACL orchagent is core SONiC,
//! so the capability is always supported). Rule rows are named
//! `RULE_<priority>` and `priority` is the rule's identity in this API.
//!
//! Only the console-managed table types (L3 / L3V6 / MAC) surface here; the
//! image's own control-plane and mirror tables (CTRLPLANE, MIRROR, …) are
//! invisible to — and protected from — this API.
//!
//! Redis stores CONFIG_DB list fields with an `@` suffix (`ports@`,
//! comma-joined); both spellings are read, the `@` form is written.
//!
//! ACL_RULE has no description field and orchagent refuses rows with unknown
//! attributes, so per-rule descriptions live in the agent-private
//! `QUARTZ_ACL_RULE_DESC` table (same key shape) — SONiC daemons ignore
//! unknown tables and `config save` carries them across reboots.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::json;

use super::probe::Capability;
use super::store::{self, field, key_suffix, row, two_parts, Platform};
use super::switching::{natural_cmp, WriteError, WriteResult};
use super::CONFIG_DB;

const DESC_TABLE: &str = "QUARTZ_ACL_RULE_DESC";
const MANAGED_TYPES: [&str; 3] = ["L3", "L3V6", "MAC"];

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

// ── GET /api/security/acls ──────────────────────────────────────────────────

fn ports_of(r: &HashMap<String, String>) -> Vec<String> {
    field(r, "ports@")
        .or_else(|| field(r, "ports"))
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

/// "tcp"/"udp"/"icmp" (per address family) or the raw number. Pure.
fn protocol_name(num: &str, v6: bool) -> String {
    match (num, v6) {
        ("6", _) => "tcp".to_string(),
        ("17", _) => "udp".to_string(),
        ("1", false) | ("58", true) => "icmp".to_string(),
        (other, _) => other.to_string(),
    }
}

fn rule_doc(
    kind: &str,
    priority: u32,
    r: &HashMap<String, String>,
    description: Option<String>,
) -> serde_json::Value {
    let v6 = kind == "L3V6";
    let (src_f, dst_f) = match kind {
        "L3V6" => ("SRC_IPV6", "DST_IPV6"),
        "MAC" => ("SRC_MAC", "DST_MAC"),
        _ => ("SRC_IP", "DST_IP"),
    };
    let port = |f: &str| {
        field(r, &format!("{f}_RANGE"))
            .map(|v| v.replace("..", "-"))
            .or_else(|| field(r, f).map(str::to_string))
    };
    json!({
        "priority": priority,
        "action": match field(r, "PACKET_ACTION").map(str::to_ascii_uppercase).as_deref() {
            Some("DROP") | Some("DENY") => "drop",
            _ => "forward",
        },
        "description": description,
        "src": field(r, src_f),
        "dst": field(r, dst_f),
        "protocol": field(r, "IP_PROTOCOL").map(|p| protocol_name(p, v6)),
        "src_port": port("L4_SRC_PORT"),
        "dst_port": port("L4_DST_PORT"),
    })
}

/// (priority, ACL_RULE row) lists keyed by table name.
type RulesByTable = HashMap<String, Vec<(u32, HashMap<String, String>)>>;

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    // Rules and stashed descriptions, grouped by table.
    let mut rules_by_table: RulesByTable = HashMap::new();
    for key in plat.scan(CONFIG_DB, "ACL_RULE|*")? {
        let Some((table, rule)) = two_parts(&key, "ACL_RULE|") else { continue };
        let r = row(plat, CONFIG_DB, &key);
        let priority = field(&r, "PRIORITY")
            .and_then(|v| v.parse().ok())
            .or_else(|| rule.strip_prefix("RULE_").and_then(|v| v.parse().ok()));
        if let Some(priority) = priority {
            rules_by_table.entry(table.to_string()).or_default().push((priority, r));
        }
    }

    let mut tables = Vec::new();
    for key in plat.scan(CONFIG_DB, "ACL_TABLE|*")? {
        let Some(name) = key_suffix(&key, "ACL_TABLE|") else { continue };
        let r = row(plat, CONFIG_DB, &key);
        let kind = field(&r, "type").map(str::to_ascii_uppercase).unwrap_or_default();
        if !MANAGED_TYPES.contains(&kind.as_str()) {
            continue;
        }
        let mut rules = rules_by_table.remove(name).unwrap_or_default();
        rules.sort_by_key(|(priority, _)| std::cmp::Reverse(*priority)); // priority descending
        let rules: Vec<serde_json::Value> = rules
            .iter()
            .map(|(priority, rule)| {
                let desc = field(
                    &row(plat, CONFIG_DB, &format!("{DESC_TABLE}|{name}|RULE_{priority}")),
                    "description",
                )
                .map(str::to_string);
                rule_doc(&kind, *priority, rule, desc)
            })
            .collect();
        let stage = match field(&r, "stage").map(str::to_ascii_lowercase).as_deref() {
            Some("egress") => "egress",
            _ => "ingress",
        };
        tables.push(json!({
            "name": name,
            "type": kind,
            "stage": stage,
            "description": field(&r, "policy_desc"),
            "ports": ports_of(&r),
            "rules": rules,
        }));
    }
    tables.sort_by(|a, b| natural_cmp(a["name"].as_str().unwrap(), b["name"].as_str().unwrap()));
    Ok(json!({ "capability": Capability::yes(), "tables": tables }))
}

// ── table validation ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TableInput {
    #[serde(rename = "type")]
    pub kind: String,
    pub stage: String,
    pub description: Option<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TableCreate {
    pub name: String,
    #[serde(flatten)]
    pub input: TableInput,
}

pub fn valid_table_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn check_table_input(plat: &mut dyn Platform, input: &TableInput) -> WriteResult {
    if !MANAGED_TYPES.contains(&input.kind.as_str()) {
        return Err(bad(format!("invalid type {:?} (L3, L3V6, or MAC)", input.kind)));
    }
    if input.stage != "ingress" && input.stage != "egress" {
        return Err(bad(format!("invalid stage {:?} (ingress or egress)", input.stage)));
    }
    if let Some(d) = &input.description {
        if d.len() > 255 || d.bytes().any(|b| !(0x20..0x7f).contains(&b)) {
            return Err(bad("invalid description: printable ASCII, 255 chars max"));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for p in &input.ports {
        if !seen.insert(p.as_str()) {
            return Err(bad(format!("duplicate port {p}")));
        }
        let table = if p.starts_with("PortChannel") {
            "PORTCHANNEL"
        } else if p.starts_with("Vlan") {
            "VLAN"
        } else {
            "PORT"
        };
        if !plat.exists(CONFIG_DB, &format!("{table}|{p}")).map_err(WriteError::Redis)? {
            return Err(bad(format!("no such interface {p}")));
        }
    }
    Ok(())
}

/// An existing table this API is allowed to touch: exists, and is one of the
/// managed types.
fn managed_table(
    plat: &mut dyn Platform,
    name: &str,
) -> std::result::Result<HashMap<String, String>, WriteError> {
    let r = plat
        .hgetall(CONFIG_DB, &format!("ACL_TABLE|{name}"))
        .map_err(WriteError::Redis)?;
    if r.is_empty() {
        return Err(WriteError::NotFound(format!("no such ACL table {name}")));
    }
    let kind = field(&r, "type").map(str::to_ascii_uppercase).unwrap_or_default();
    if !MANAGED_TYPES.contains(&kind.as_str()) {
        return Err(WriteError::Conflict(format!(
            "ACL table {name} (type {kind}) is not managed by this API"
        )));
    }
    Ok(r)
}

fn table_fields<'a>(input: &'a TableInput, ports: &'a str) -> Vec<(&'static str, &'a str)> {
    let mut fields = vec![
        ("type", input.kind.as_str()),
        ("stage", input.stage.as_str()),
        ("ports@", ports),
    ];
    if let Some(d) = &input.description {
        fields.push(("policy_desc", d.as_str()));
    }
    fields
}

// ── table writes ────────────────────────────────────────────────────────────

pub fn create_table(plat: &mut dyn Platform, create: &TableCreate) -> WriteResult {
    let _lock = store::feature_lock("acl");
    if !valid_table_name(&create.name) {
        return Err(bad(format!(
            "invalid ACL table name {:?} (letters, digits, - and _; 64 chars max)",
            create.name
        )));
    }
    if plat
        .exists(CONFIG_DB, &format!("ACL_TABLE|{}", create.name))
        .map_err(WriteError::Redis)?
    {
        return Err(WriteError::Conflict(format!("ACL table {} already exists", create.name)));
    }
    check_table_input(plat, &create.input)?;
    let ports = create.input.ports.join(",");
    plat.hset(
        CONFIG_DB,
        &format!("ACL_TABLE|{}", create.name),
        &table_fields(&create.input, &ports),
    )
    .map_err(WriteError::Redis)
}

pub fn update_table(plat: &mut dyn Platform, name: &str, input: &TableInput) -> WriteResult {
    let _lock = store::feature_lock("acl");
    let cur = managed_table(plat, name)?;
    // The type decides which SAI table the rules compile into — SONiC cannot
    // change it in place.
    let cur_kind = field(&cur, "type").map(str::to_ascii_uppercase).unwrap_or_default();
    if cur_kind != input.kind {
        return Err(WriteError::Conflict(format!(
            "ACL table type is immutable in SONiC ({cur_kind} → {}); delete and re-create the table",
            input.kind
        )));
    }
    check_table_input(plat, input)?;
    let ports = input.ports.join(",");
    let key = format!("ACL_TABLE|{name}");
    store::apply(plat, |b| {
        b.hset(CONFIG_DB, &key, &table_fields(input, &ports))?;
        if input.description.is_none() {
            b.hdel(CONFIG_DB, &key, &["policy_desc"])?;
        }
        // Clear a legacy non-@ ports field so the row has one source of truth.
        b.hdel(CONFIG_DB, &key, &["ports"])
    })
    .map_err(WriteError::Redis)
}

pub fn delete_table(plat: &mut dyn Platform, name: &str) -> WriteResult {
    let _lock = store::feature_lock("acl");
    managed_table(plat, name)?;
    for pattern in [format!("ACL_RULE|{name}|*"), format!("{DESC_TABLE}|{name}|*")] {
        for key in plat.scan(CONFIG_DB, &pattern).map_err(WriteError::Redis)? {
            plat.del(CONFIG_DB, &key).map_err(WriteError::Redis)?;
        }
    }
    plat.del(CONFIG_DB, &format!("ACL_TABLE|{name}")).map_err(WriteError::Redis)
}

// ── rule writes ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RuleInput {
    pub action: String,
    pub description: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub protocol: Option<String>,
    pub src_port: Option<String>,
    pub dst_port: Option<String>,
}

fn check_match_addr(kind: &str, what: &str, v: &str) -> std::result::Result<(), String> {
    let err = || format!("invalid {what} {v:?} for a {kind} table");
    match kind {
        "MAC" => {
            let parts: Vec<&str> = v.split(':').collect();
            let ok = parts.len() == 6
                && parts.iter().all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()));
            if ok { Ok(()) } else { Err(err()) }
        }
        _ => {
            let v6 = kind == "L3V6";
            let (ip, len) = match v.split_once('/') {
                Some((ip, len)) => (ip, Some(len)),
                None => (v, None),
            };
            let ip: std::net::IpAddr = ip.parse().map_err(|_| err())?;
            if ip.is_ipv4() == v6 {
                return Err(err());
            }
            if let Some(len) = len {
                let len: u8 = len.parse().map_err(|_| err())?;
                if len > if v6 { 128 } else { 32 } {
                    return Err(err());
                }
            }
            Ok(())
        }
    }
}

/// "22" → (L4_x_PORT, "22"); "1024-65535" → (L4_x_PORT_RANGE, "1024-65535").
fn port_field(
    what: &str,
    base: &'static str,
    v: &str,
) -> std::result::Result<(String, String), String> {
    let err = || format!("invalid {what} {v:?} (a port or lo-hi range)");
    match v.split_once('-') {
        Some((lo, hi)) => {
            let lo: u16 = lo.parse().map_err(|_| err())?;
            let hi: u16 = hi.parse().map_err(|_| err())?;
            if lo >= hi {
                return Err(err());
            }
            Ok((format!("{base}_RANGE"), format!("{lo}-{hi}")))
        }
        None => {
            let p: u16 = v.parse().map_err(|_| err())?;
            Ok((base.to_string(), p.to_string()))
        }
    }
}

fn protocol_number(kind: &str, v: &str) -> std::result::Result<String, String> {
    match v {
        "tcp" => Ok("6".to_string()),
        "udp" => Ok("17".to_string()),
        "icmp" => Ok(if kind == "L3V6" { "58" } else { "1" }.to_string()),
        other => match other.parse::<u16>() {
            Ok(n) if n <= 255 => Ok(n.to_string()),
            _ => Err(format!("invalid protocol {v:?} (tcp, udp, icmp, or 0-255)")),
        },
    }
}

/// Compile a rule input into its ACL_RULE fields for the table's type. Pure
/// aside from validation.
fn rule_fields(
    kind: &str,
    priority: u32,
    input: &RuleInput,
) -> std::result::Result<Vec<(String, String)>, String> {
    let mut fields = vec![("PRIORITY".to_string(), priority.to_string())];
    match input.action.as_str() {
        "forward" => fields.push(("PACKET_ACTION".to_string(), "FORWARD".to_string())),
        "drop" => fields.push(("PACKET_ACTION".to_string(), "DROP".to_string())),
        other => return Err(format!("invalid action {other:?} (forward or drop)")),
    }
    let (src_f, dst_f) = match kind {
        "L3V6" => ("SRC_IPV6", "DST_IPV6"),
        "MAC" => ("SRC_MAC", "DST_MAC"),
        _ => ("SRC_IP", "DST_IP"),
    };
    if let Some(v) = &input.src {
        check_match_addr(kind, "src", v)?;
        fields.push((src_f.to_string(), v.clone()));
    }
    if let Some(v) = &input.dst {
        check_match_addr(kind, "dst", v)?;
        fields.push((dst_f.to_string(), v.clone()));
    }
    let protocol = match &input.protocol {
        Some(v) if kind == "MAC" => {
            return Err(format!("protocol {v:?} does not apply to a MAC table"));
        }
        Some(v) => {
            let num = protocol_number(kind, v)?;
            fields.push(("IP_PROTOCOL".to_string(), num.clone()));
            Some(num)
        }
        None => None,
    };
    let l4_ok = matches!(protocol.as_deref(), Some("6") | Some("17"));
    for (what, base, v) in [
        ("src_port", "L4_SRC_PORT", &input.src_port),
        ("dst_port", "L4_DST_PORT", &input.dst_port),
    ] {
        if let Some(v) = v {
            if !l4_ok {
                return Err(format!("{what} requires protocol tcp or udp"));
            }
            let (f, v) = port_field(what, base, v)?;
            fields.push((f, v));
        }
    }
    Ok(fields)
}

pub fn check_priority(priority: u32) -> std::result::Result<(), String> {
    if (1..=65535).contains(&priority) {
        Ok(())
    } else {
        Err(format!("invalid priority {priority} (must be 1-65535)"))
    }
}

/// PUT /api/security/acls/{name}/rules/{priority} — upsert (full replace).
pub fn put_rule(
    plat: &mut dyn Platform,
    table: &str,
    priority: u32,
    input: &RuleInput,
) -> WriteResult {
    let _lock = store::feature_lock("acl");
    check_priority(priority).map_err(bad)?;
    let t = managed_table(plat, table)?;
    let kind = field(&t, "type").map(str::to_ascii_uppercase).unwrap_or_default();
    if let Some(d) = &input.description {
        if d.len() > 255 || d.bytes().any(|b| !(0x20..0x7f).contains(&b)) {
            return Err(bad("invalid description: printable ASCII, 255 chars max"));
        }
    }
    let fields = rule_fields(&kind, priority, input).map_err(bad)?;
    let fields: Vec<(&str, &str)> = fields.iter().map(|(f, v)| (f.as_str(), v.as_str())).collect();
    let rule_key = format!("ACL_RULE|{table}|RULE_{priority}");
    let desc_key = format!("{DESC_TABLE}|{table}|RULE_{priority}");
    store::apply(plat, |b| {
        // Full replace: stale match fields must not linger.
        b.del(CONFIG_DB, &rule_key)?;
        b.hset(CONFIG_DB, &rule_key, &fields)?;
        match &input.description {
            Some(d) => b.hset(CONFIG_DB, &desc_key, &[("description", d)]),
            None => b.del(CONFIG_DB, &desc_key),
        }
    })
    .map_err(WriteError::Redis)
}

pub fn delete_rule(plat: &mut dyn Platform, table: &str, priority: u32) -> WriteResult {
    let _lock = store::feature_lock("acl");
    managed_table(plat, table)?;
    let rule_key = format!("ACL_RULE|{table}|RULE_{priority}");
    if !plat.exists(CONFIG_DB, &rule_key).map_err(WriteError::Redis)? {
        return Err(WriteError::NotFound(format!(
            "no rule with priority {priority} in ACL table {table}"
        )));
    }
    plat.del(CONFIG_DB, &rule_key).map_err(WriteError::Redis)?;
    plat.del(CONFIG_DB, &format!("{DESC_TABLE}|{table}|RULE_{priority}"))
        .map_err(WriteError::Redis)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::store::mem::MemPlatform;
    use super::*;

    fn platform() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed(CONFIG_DB, "PORT|Ethernet0", &[("admin_status", "up")]);
        m.seed(CONFIG_DB, "PORT|Ethernet4", &[("admin_status", "up")]);
        m.seed(CONFIG_DB, "PORTCHANNEL|PortChannel1", &[("admin_status", "up")]);
        m.seed(CONFIG_DB, "VLAN|Vlan10", &[("vlanid", "10")]);
        m
    }

    fn l3_input(ports: &[&str]) -> TableInput {
        TableInput {
            kind: "L3".into(),
            stage: "ingress".into(),
            description: Some("server protect".into()),
            ports: ports.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn rule(action: &str) -> RuleInput {
        RuleInput {
            action: action.into(),
            description: None,
            src: None,
            dst: None,
            protocol: None,
            src_port: None,
            dst_port: None,
        }
    }

    #[test]
    fn get_maps_tables_and_rules() {
        let mut m = platform();
        m.seed(
            CONFIG_DB,
            "ACL_TABLE|SERVER-PROTECT",
            &[
                ("type", "L3"),
                ("stage", "ingress"),
                ("policy_desc", "protect"),
                ("ports@", "Ethernet0,PortChannel1"),
            ],
        );
        m.seed(
            CONFIG_DB,
            "ACL_RULE|SERVER-PROTECT|RULE_100",
            &[
                ("PRIORITY", "100"),
                ("PACKET_ACTION", "DROP"),
                ("SRC_IP", "10.0.0.0/24"),
                ("IP_PROTOCOL", "6"),
                ("L4_DST_PORT_RANGE", "1024-65535"),
            ],
        );
        m.seed(
            CONFIG_DB,
            "ACL_RULE|SERVER-PROTECT|RULE_200",
            &[("PRIORITY", "200"), ("PACKET_ACTION", "FORWARD"), ("L4_SRC_PORT", "22"), ("IP_PROTOCOL", "17")],
        );
        m.seed(
            CONFIG_DB,
            "QUARTZ_ACL_RULE_DESC|SERVER-PROTECT|RULE_100",
            &[("description", "block high ports")],
        );
        // Non-managed tables never surface.
        m.seed(CONFIG_DB, "ACL_TABLE|EVERFLOW", &[("type", "MIRROR"), ("stage", "ingress")]);
        let doc = get(&mut m).unwrap();
        let tables = doc["tables"].as_array().unwrap();
        assert_eq!(tables.len(), 1);
        let t = &tables[0];
        assert_eq!(t["name"], "SERVER-PROTECT");
        assert_eq!(t["type"], "L3");
        assert_eq!(t["description"], "protect");
        assert_eq!(t["ports"], json!(["Ethernet0", "PortChannel1"]));
        let rules = t["rules"].as_array().unwrap();
        // Priority descending.
        assert_eq!(rules[0]["priority"], 200);
        assert_eq!(rules[0]["action"], "forward");
        assert_eq!(rules[0]["protocol"], "udp");
        assert_eq!(rules[0]["src_port"], "22");
        assert_eq!(rules[1]["priority"], 100);
        assert_eq!(rules[1]["action"], "drop");
        assert_eq!(rules[1]["src"], "10.0.0.0/24");
        assert_eq!(rules[1]["protocol"], "tcp");
        assert_eq!(rules[1]["dst_port"], "1024-65535");
        assert_eq!(rules[1]["description"], "block high ports");
    }

    #[test]
    fn table_lifecycle() {
        let mut m = platform();
        create_table(
            &mut m,
            &TableCreate { name: "SERVER-PROTECT".into(), input: l3_input(&["Ethernet0", "Vlan10"]) },
        )
        .unwrap();
        let r = m.row(CONFIG_DB, "ACL_TABLE|SERVER-PROTECT");
        assert_eq!(r.get("type").unwrap(), "L3");
        assert_eq!(r.get("stage").unwrap(), "ingress");
        assert_eq!(r.get("ports@").unwrap(), "Ethernet0,Vlan10");
        assert_eq!(r.get("policy_desc").unwrap(), "server protect");
        // Duplicate create → 409.
        let err = create_table(
            &mut m,
            &TableCreate { name: "SERVER-PROTECT".into(), input: l3_input(&[]) },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));

        // Update converges ports/stage; type change is refused.
        let mut input = l3_input(&["Ethernet4"]);
        input.stage = "egress".into();
        input.description = None;
        update_table(&mut m, "SERVER-PROTECT", &input).unwrap();
        let r = m.row(CONFIG_DB, "ACL_TABLE|SERVER-PROTECT");
        assert_eq!(r.get("stage").unwrap(), "egress");
        assert_eq!(r.get("ports@").unwrap(), "Ethernet4");
        assert!(!r.contains_key("policy_desc"));
        let mut v6 = l3_input(&[]);
        v6.kind = "L3V6".into();
        let err = update_table(&mut m, "SERVER-PROTECT", &v6).unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));

        // Delete removes rules and stashed descriptions too.
        m.seed(CONFIG_DB, "ACL_RULE|SERVER-PROTECT|RULE_100", &[("PRIORITY", "100")]);
        m.seed(CONFIG_DB, "QUARTZ_ACL_RULE_DESC|SERVER-PROTECT|RULE_100", &[("description", "x")]);
        delete_table(&mut m, "SERVER-PROTECT").unwrap();
        assert!(!m.has_key(CONFIG_DB, "ACL_TABLE|SERVER-PROTECT"));
        assert!(!m.has_key(CONFIG_DB, "ACL_RULE|SERVER-PROTECT|RULE_100"));
        assert!(!m.has_key(CONFIG_DB, "QUARTZ_ACL_RULE_DESC|SERVER-PROTECT|RULE_100"));
        let err = delete_table(&mut m, "SERVER-PROTECT").unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
    }

    #[test]
    fn table_validation() {
        let mut m = platform();
        for (name, input) in [
            ("bad name", l3_input(&[])),
            ("OK", TableInput { kind: "L4".into(), ..l3_input(&[]) }),
            ("OK", TableInput { stage: "sideways".into(), ..l3_input(&[]) }),
            ("OK", l3_input(&["Ethernet99"])),
            ("OK", l3_input(&["Ethernet0", "Ethernet0"])),
        ] {
            let err = create_table(&mut m, &TableCreate { name: name.into(), input }).unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{name}");
        }
        // Foreign tables are never modified through this API.
        m.seed(CONFIG_DB, "ACL_TABLE|EVERFLOW", &[("type", "MIRROR")]);
        let err = update_table(&mut m, "EVERFLOW", &l3_input(&[])).unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
        let err = delete_table(&mut m, "EVERFLOW").unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
    }

    #[test]
    fn rule_upsert_by_table_type() {
        let mut m = platform();
        create_table(
            &mut m,
            &TableCreate { name: "T4".into(), input: l3_input(&["Ethernet0"]) },
        )
        .unwrap();
        put_rule(
            &mut m,
            "T4",
            100,
            &RuleInput {
                description: Some("ssh in".into()),
                src: Some("10.0.0.0/24".into()),
                protocol: Some("tcp".into()),
                dst_port: Some("22".into()),
                ..rule("forward")
            },
        )
        .unwrap();
        let r = m.row(CONFIG_DB, "ACL_RULE|T4|RULE_100");
        assert_eq!(r.get("PRIORITY").unwrap(), "100");
        assert_eq!(r.get("PACKET_ACTION").unwrap(), "FORWARD");
        assert_eq!(r.get("SRC_IP").unwrap(), "10.0.0.0/24");
        assert_eq!(r.get("IP_PROTOCOL").unwrap(), "6");
        assert_eq!(r.get("L4_DST_PORT").unwrap(), "22");
        assert_eq!(
            m.row(CONFIG_DB, "QUARTZ_ACL_RULE_DESC|T4|RULE_100").get("description").unwrap(),
            "ssh in"
        );

        // Upsert replaces wholesale: stale fields and the description go.
        put_rule(
            &mut m,
            "T4",
            100,
            &RuleInput {
                dst: Some("10.9.9.9".into()),
                protocol: Some("udp".into()),
                src_port: Some("1024-65535".into()),
                ..rule("drop")
            },
        )
        .unwrap();
        let r = m.row(CONFIG_DB, "ACL_RULE|T4|RULE_100");
        assert_eq!(r.get("PACKET_ACTION").unwrap(), "DROP");
        assert!(!r.contains_key("SRC_IP"));
        assert!(!r.contains_key("L4_DST_PORT"));
        assert_eq!(r.get("DST_IP").unwrap(), "10.9.9.9");
        assert_eq!(r.get("IP_PROTOCOL").unwrap(), "17");
        assert_eq!(r.get("L4_SRC_PORT_RANGE").unwrap(), "1024-65535");
        assert!(!m.has_key(CONFIG_DB, "QUARTZ_ACL_RULE_DESC|T4|RULE_100"));

        // V6 and MAC field mapping.
        let mut v6 = l3_input(&[]);
        v6.kind = "L3V6".into();
        create_table(&mut m, &TableCreate { name: "T6".into(), input: v6 }).unwrap();
        put_rule(
            &mut m,
            "T6",
            10,
            &RuleInput { src: Some("fd00::/64".into()), protocol: Some("icmp".into()), ..rule("drop") },
        )
        .unwrap();
        let r = m.row(CONFIG_DB, "ACL_RULE|T6|RULE_10");
        assert_eq!(r.get("SRC_IPV6").unwrap(), "fd00::/64");
        assert_eq!(r.get("IP_PROTOCOL").unwrap(), "58"); // icmpv6

        let mut mac = l3_input(&[]);
        mac.kind = "MAC".into();
        create_table(&mut m, &TableCreate { name: "TM".into(), input: mac }).unwrap();
        put_rule(
            &mut m,
            "TM",
            10,
            &RuleInput { src: Some("00:11:22:33:44:55".into()), ..rule("drop") },
        )
        .unwrap();
        assert_eq!(
            m.row(CONFIG_DB, "ACL_RULE|TM|RULE_10").get("SRC_MAC").unwrap(),
            "00:11:22:33:44:55"
        );
    }

    #[test]
    fn rule_validation() {
        let mut m = platform();
        create_table(&mut m, &TableCreate { name: "T4".into(), input: l3_input(&[]) }).unwrap();
        let cases: Vec<RuleInput> = vec![
            rule("allow"),
            RuleInput { src: Some("fd00::/64".into()), ..rule("drop") }, // family mismatch
            RuleInput { src: Some("10.0.0.0/33".into()), ..rule("drop") },
            RuleInput { protocol: Some("999".into()), ..rule("drop") },
            RuleInput { src_port: Some("22".into()), ..rule("drop") }, // ports need tcp/udp
            RuleInput {
                protocol: Some("icmp".into()),
                src_port: Some("22".into()),
                ..rule("drop")
            },
            RuleInput {
                protocol: Some("tcp".into()),
                src_port: Some("9-1".into()), // inverted range
                ..rule("drop")
            },
        ];
        for input in cases {
            let err = put_rule(&mut m, "T4", 100, &input).unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{input:?}");
        }
        // Bad priority, unknown table, unknown rule.
        let err = put_rule(&mut m, "T4", 0, &rule("drop")).unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
        let err = put_rule(&mut m, "NOPE", 100, &rule("drop")).unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
        let err = delete_rule(&mut m, "T4", 100).unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
        // MAC tables take no protocol.
        let mut mac = l3_input(&[]);
        mac.kind = "MAC".into();
        create_table(&mut m, &TableCreate { name: "TM".into(), input: mac }).unwrap();
        let err = put_rule(
            &mut m,
            "TM",
            10,
            &RuleInput { protocol: Some("tcp".into()), ..rule("drop") },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
    }

    #[test]
    fn rule_delete_removes_description() {
        let mut m = platform();
        create_table(&mut m, &TableCreate { name: "T4".into(), input: l3_input(&[]) }).unwrap();
        put_rule(
            &mut m,
            "T4",
            100,
            &RuleInput { description: Some("x".into()), src: Some("10.0.0.1".into()), ..rule("drop") },
        )
        .unwrap();
        delete_rule(&mut m, "T4", 100).unwrap();
        assert!(!m.has_key(CONFIG_DB, "ACL_RULE|T4|RULE_100"));
        assert!(!m.has_key(CONFIG_DB, "QUARTZ_ACL_RULE_DESC|T4|RULE_100"));
    }
}
