//! MAC table / FDB for the console's MAC Table pages: aging time and static
//! entries (config), plus the learned table (read-only).
//!
//! Config side: CONFIG_DB `SWITCH|switch` `fdb_aging_time` and static
//! entries in the CONFIG_DB `FDB` table (key `FDB|Vlan<id>:<mac>`, fields
//! `port`, `type=static`). Both knobs are consumed by orchagent since
//! community 202205 (and on enterprise); older images report read_only.
//!
//! Read side: the learned table exactly as `show mac` assembles it — ASIC_DB
//! `ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:{json}` entries, bridge-port oids
//! resolved through `SAI_OBJECT_TYPE_BRIDGE_PORT` to port oids, port oids to
//! names through the COUNTERS_DB name maps, and bvids to VLAN ids through
//! `SAI_OBJECT_TYPE_VLAN`. Entries that can't be fully resolved (a row
//! caught mid-teardown) are skipped, as fdbshow does.
//!
//! MACs travel colon-separated lowercase in both directions; reads and the
//! path parameters normalize whatever separator/case they receive.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, field, keys, row, Platform};
use super::switching::{parse_num, WriteError, WriteResult};
use super::{ASIC_DB, CONFIG_DB, COUNTERS_DB};

const READ_ONLY_REASON: &str =
    "MAC table configuration (aging time, static entries) requires community SONiC \
     202205 or newer; the learned table is still shown.";

/// SONiC's default FDB aging time when SWITCH|switch carries no override.
const AGING_DEFAULT_SECS: u64 = 600;

/// The learned table is capped so one busy switch can't produce an unbounded
/// proxy response; the document says so via `truncated`/`total_entries`.
const TABLE_CAP: usize = 20_000;

/// Canonicalize any common MAC spelling (colons, hyphens, dots, bare hex, any
/// case) to colon-separated lowercase. None when it isn't 12 hex digits.
pub fn normalize_mac(input: &str) -> Option<String> {
    let hex: String = input
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.len() != 12 || input.chars().any(|c| !c.is_ascii_hexdigit() && !":-. ".contains(c)) {
        return None;
    }
    let pairs: Vec<&str> = (0..6).map(|i| &hex[i * 2..i * 2 + 2]).collect();
    Some(pairs.join(":"))
}

fn capability(writable: bool) -> Capability {
    if writable {
        Capability::yes()
    } else {
        Capability { supported: true, read_only: true, reason: Some(READ_ONLY_REASON.into()) }
    }
}

// ── GET /api/switching/fdb (config) ─────────────────────────────────────────

#[derive(Debug, Serialize)]
struct StaticEntryDoc {
    vlan_id: u32,
    mac: String,
    port: String,
}

/// "Vlan10:00:11:22:33:44:55" (an FDB key's suffix) → (10, normalized mac).
pub fn parse_static_key(suffix: &str) -> Option<(u32, String)> {
    let (vlan, mac) = suffix.split_once(':')?;
    let id = super::switching::vlan_id_from_name(vlan)?;
    Some((id, normalize_mac(mac)?))
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    let switch = row(plat, CONFIG_DB, "SWITCH|switch");
    let mut entries = Vec::new();
    for key in keys(plat, CONFIG_DB, "FDB|*") {
        let Some(suffix) = key.strip_prefix("FDB|") else { continue };
        let Some((vlan_id, mac)) = parse_static_key(suffix) else { continue };
        let r = row(plat, CONFIG_DB, &key);
        let Some(port) = field(&r, "port") else { continue };
        entries.push(StaticEntryDoc { vlan_id, mac, port: port.to_string() });
    }
    entries.sort_by(|a, b| a.vlan_id.cmp(&b.vlan_id).then_with(|| a.mac.cmp(&b.mac)));
    Ok(json!({
        "capability": capability(p.fdb_config_writable()),
        "aging_time_seconds": parse_num(field(&switch, "fdb_aging_time")),
        "aging_time_default": AGING_DEFAULT_SECS,
        "static_entries": entries,
    }))
}

// ── PUT /api/switching/fdb/settings ─────────────────────────────────────────

/// null restores the image default; 0 disables aging entirely.
#[derive(Debug, Deserialize)]
pub struct SettingsInput {
    pub aging_time_seconds: Option<u64>,
}

fn check_writable(plat: &mut dyn Platform) -> WriteResult {
    if !probe::current(plat).fdb_config_writable() {
        return Err(WriteError::Conflict(READ_ONLY_REASON.to_string()));
    }
    Ok(())
}

pub fn put_settings(plat: &mut dyn Platform, input: &SettingsInput) -> WriteResult {
    let _lock = store::feature_lock("fdb");
    if let Some(v) = input.aging_time_seconds {
        if v > 1_000_000 {
            return Err(WriteError::BadRequest(format!(
                "invalid aging_time_seconds {v} (must be 0-1000000)"
            )));
        }
    }
    check_writable(plat)?;
    match input.aging_time_seconds {
        Some(v) => {
            plat.hset(CONFIG_DB, "SWITCH|switch", &[("fdb_aging_time", &v.to_string())])?
        }
        None => plat.hdel(CONFIG_DB, "SWITCH|switch", &["fdb_aging_time"])?,
    }
    Ok(())
}

// ── PUT/DELETE /api/switching/fdb/static/{vlan_id}/{mac} ────────────────────

#[derive(Debug, Deserialize)]
pub struct StaticEntryInput {
    pub port: String,
}

/// The path MAC, normalized, with unicast-only enforcement — a 400 message
/// otherwise.
fn check_mac(mac: &str) -> std::result::Result<String, WriteError> {
    let Some(canonical) = normalize_mac(mac) else {
        return Err(WriteError::BadRequest(format!(
            "invalid MAC address {mac:?} (expected e.g. 00:11:22:33:44:55)"
        )));
    };
    let first = u8::from_str_radix(&canonical[..2], 16).expect("normalized hex");
    if first & 1 == 1 {
        return Err(WriteError::BadRequest(format!(
            "{canonical} is a multicast address; static FDB entries must be unicast"
        )));
    }
    if canonical == "00:00:00:00:00:00" {
        return Err(WriteError::BadRequest("the all-zero MAC address is not valid".into()));
    }
    Ok(canonical)
}

/// Existing FDB keys for (vlan, mac) whatever spelling the image used.
fn matching_static_keys(
    plat: &mut dyn Platform,
    vlan_id: u32,
    mac: &str,
) -> anyhow::Result<Vec<String>> {
    let mut found = Vec::new();
    for key in plat.scan(CONFIG_DB, &format!("FDB|Vlan{vlan_id}:*"))? {
        if let Some(suffix) = key.strip_prefix("FDB|") {
            if parse_static_key(suffix).is_some_and(|(id, m)| id == vlan_id && m == mac) {
                found.push(key);
            }
        }
    }
    Ok(found)
}

pub fn put_static(
    plat: &mut dyn Platform,
    vlan_id: u32,
    mac: &str,
    input: &StaticEntryInput,
) -> WriteResult {
    let _lock = store::feature_lock("fdb");
    let mac = check_mac(mac)?;
    check_writable(plat)?;
    if !plat.exists(CONFIG_DB, &format!("VLAN|Vlan{vlan_id}"))? {
        return Err(WriteError::NotFound(format!("no such VLAN Vlan{vlan_id}")));
    }
    let port = &input.port;
    if !plat.exists(CONFIG_DB, &format!("VLAN_MEMBER|Vlan{vlan_id}|{port}"))? {
        return Err(WriteError::BadRequest(format!(
            "{port} is not a member of VLAN {vlan_id}"
        )));
    }

    // Replace any spelling variant an image/tool may have written, then land
    // the canonical lowercase key.
    let canonical = format!("FDB|Vlan{vlan_id}:{mac}");
    for key in matching_static_keys(plat, vlan_id, &mac)? {
        if key != canonical {
            plat.del(CONFIG_DB, &key)?;
        }
    }
    plat.hset(CONFIG_DB, &canonical, &[("port", port.as_str()), ("type", "static")])?;
    Ok(())
}

pub fn delete_static(plat: &mut dyn Platform, vlan_id: u32, mac: &str) -> WriteResult {
    let _lock = store::feature_lock("fdb");
    let mac = check_mac(mac)?;
    check_writable(plat)?;
    let matches = matching_static_keys(plat, vlan_id, &mac)?;
    if matches.is_empty() {
        return Err(WriteError::NotFound(format!(
            "no static FDB entry for {mac} on VLAN {vlan_id}"
        )));
    }
    for key in matches {
        plat.del(CONFIG_DB, &key)?;
    }
    Ok(())
}

// ── GET /api/switching/fdb/table (learned) ──────────────────────────────────

#[derive(Debug, Serialize)]
struct TableEntryDoc {
    vlan_id: u32,
    mac: String,
    port: String,
    origin: &'static str,
}

/// Parse an ASIC_DB FDB key's JSON tail into (bvid, normalized mac). Pure.
pub fn parse_asic_fdb_key(key: &str) -> Option<(String, String)> {
    let tail = key.strip_prefix("ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:")?;
    let v: serde_json::Value = serde_json::from_str(tail).ok()?;
    let bvid = v.get("bvid")?.as_str()?.to_string();
    let mac = normalize_mac(v.get("mac")?.as_str()?)?;
    Some((bvid, mac))
}

pub fn get_table(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let entry_keys = keys(plat, ASIC_DB, "ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*");
    // SAI object id → interface name, physical ports and LAGs alike.
    let mut oid_names: HashMap<String, String> = HashMap::new();
    for map in ["COUNTERS_PORT_NAME_MAP", "COUNTERS_LAG_NAME_MAP"] {
        for (name, oid) in row(plat, COUNTERS_DB, map) {
            oid_names.insert(oid, name);
        }
    }
    let mut vlan_of_bvid: HashMap<String, Option<u32>> = HashMap::new();
    let mut port_of_bridge: HashMap<String, Option<String>> = HashMap::new();
    let mut entries = Vec::new();
    for key in &entry_keys {
        let Some((bvid, mac)) = parse_asic_fdb_key(key) else { continue };
        if !vlan_of_bvid.contains_key(&bvid) {
            let vlan_row = row(plat, ASIC_DB, &format!("ASIC_STATE:SAI_OBJECT_TYPE_VLAN:{bvid}"));
            let id = parse_num(field(&vlan_row, "SAI_VLAN_ATTR_VLAN_ID"))
                .and_then(|n| u32::try_from(n).ok());
            vlan_of_bvid.insert(bvid.clone(), id);
        }
        let Some(vlan_id) = vlan_of_bvid[&bvid] else { continue };
        let entry = row(plat, ASIC_DB, key);
        let Some(bridge_oid) = field(&entry, "SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID") else {
            continue;
        };
        if !port_of_bridge.contains_key(bridge_oid) {
            let bridge = row(
                plat,
                ASIC_DB,
                &format!("ASIC_STATE:SAI_OBJECT_TYPE_BRIDGE_PORT:{bridge_oid}"),
            );
            let name = field(&bridge, "SAI_BRIDGE_PORT_ATTR_PORT_ID")
                .and_then(|oid| oid_names.get(oid))
                .cloned();
            port_of_bridge.insert(bridge_oid.to_string(), name);
        }
        let Some(port) = port_of_bridge[bridge_oid].clone() else { continue };
        let origin = if field(&entry, "SAI_FDB_ENTRY_ATTR_TYPE")
            .is_some_and(|t| t.contains("STATIC"))
        {
            "static"
        } else {
            "dynamic"
        };
        entries.push(TableEntryDoc { vlan_id, mac, port, origin });
    }
    entries.sort_by(|a, b| a.vlan_id.cmp(&b.vlan_id).then_with(|| a.mac.cmp(&b.mac)));
    let total = entries.len();
    let truncated = total > TABLE_CAP;
    entries.truncate(TABLE_CAP);
    Ok(json!({
        "capability": Capability::yes(),
        "entries": entries,
        "truncated": truncated,
        "total_entries": total,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::*;

    fn platform(release: &str) -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file(
            "/etc/sonic/sonic_version.yml",
            &format!("build_version: '{release}'\n"),
        );
        m.seed(CONFIG_DB, "VLAN|Vlan10", &[("vlanid", "10")]);
        m.seed(CONFIG_DB, "VLAN_MEMBER|Vlan10|Ethernet4", &[("tagging_mode", "untagged")]);
        m
    }

    #[test]
    fn normalizes_common_mac_spellings() {
        for input in [
            "00:11:22:33:44:55",
            "00-11-22-33-44-55",
            "0011.2233.4455",
            "001122334455",
            "00:11:22:33:44:55 ",
            "00:11:22:33:44:55".to_uppercase().as_str(),
        ] {
            assert_eq!(normalize_mac(input).as_deref(), Some("00:11:22:33:44:55"), "{input}");
        }
        assert_eq!(normalize_mac("00:11:22:33:44"), None);
        assert_eq!(normalize_mac("00:11:22:33:44:5g"), None);
        assert_eq!(normalize_mac("hello world!"), None);
        assert_eq!(normalize_mac(""), None);
    }

    #[test]
    fn config_get_reports_aging_and_static_entries() {
        let mut m = platform("202305.1");
        m.seed(CONFIG_DB, "SWITCH|switch", &[("fdb_aging_time", "300")]);
        // An uppercase entry written by other tooling is normalized on read.
        m.seed(
            CONFIG_DB,
            "FDB|Vlan10:AA:BB:CC:00:11:22",
            &[("port", "Ethernet4"), ("type", "static")],
        );
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["capability"]["read_only"], false);
        assert_eq!(doc["aging_time_seconds"], 300);
        assert_eq!(doc["aging_time_default"], 600);
        let entries = doc["static_entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["vlan_id"], 10);
        assert_eq!(entries[0]["mac"], "aa:bb:cc:00:11:22");
        assert_eq!(entries[0]["port"], "Ethernet4");
    }

    #[test]
    fn old_image_is_read_only_and_refuses_writes() {
        let mut m = platform("202111.9");
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["capability"]["read_only"], true);
        assert_eq!(doc["capability"]["reason"], READ_ONLY_REASON);
        assert!(matches!(
            put_settings(&mut m, &SettingsInput { aging_time_seconds: Some(300) }).unwrap_err(),
            WriteError::Conflict(_)
        ));
        assert!(matches!(
            put_static(
                &mut m,
                10,
                "00:11:22:33:44:55",
                &StaticEntryInput { port: "Ethernet4".into() },
            )
            .unwrap_err(),
            WriteError::Conflict(_)
        ));
    }

    #[test]
    fn settings_put_sets_clears_and_validates() {
        let mut m = platform("202305.1");
        put_settings(&mut m, &SettingsInput { aging_time_seconds: Some(0) }).unwrap();
        assert_eq!(m.row(CONFIG_DB, "SWITCH|switch").get("fdb_aging_time").unwrap(), "0");
        put_settings(&mut m, &SettingsInput { aging_time_seconds: None }).unwrap();
        assert!(!m.row(CONFIG_DB, "SWITCH|switch").contains_key("fdb_aging_time"));
        assert!(matches!(
            put_settings(&mut m, &SettingsInput { aging_time_seconds: Some(2_000_000) })
                .unwrap_err(),
            WriteError::BadRequest(_)
        ));
    }

    #[test]
    fn static_put_upserts_canonically() {
        let mut m = platform("202305.1");
        // A pre-existing uppercase spelling of the same entry is replaced by
        // the canonical lowercase key, not duplicated alongside it.
        m.seed(CONFIG_DB, "FDB|Vlan10:AA:BB:CC:33:44:55", &[("port", "Ethernet4")]);
        put_static(
            &mut m,
            10,
            "AA-BB-CC-33-44-55",
            &StaticEntryInput { port: "Ethernet4".into() },
        )
        .unwrap();
        let row = m.row(CONFIG_DB, "FDB|Vlan10:aa:bb:cc:33:44:55");
        assert_eq!(row.get("port").unwrap(), "Ethernet4");
        assert_eq!(row.get("type").unwrap(), "static");
        assert!(!m.has_key(CONFIG_DB, "FDB|Vlan10:AA:BB:CC:33:44:55"));
    }

    #[test]
    fn static_put_validates_vlan_membership_and_mac() {
        let mut m = platform("202305.1");
        assert!(matches!(
            put_static(&mut m, 20, "00:11:22:33:44:55", &StaticEntryInput { port: "Ethernet4".into() })
                .unwrap_err(),
            WriteError::NotFound(_)
        ));
        assert!(matches!(
            put_static(&mut m, 10, "00:11:22:33:44:55", &StaticEntryInput { port: "Ethernet0".into() })
                .unwrap_err(),
            WriteError::BadRequest(_)
        ));
        // Multicast and garbage MACs are 400s.
        for mac in ["01:00:5e:00:00:01", "nonsense", "00:00:00:00:00:00"] {
            assert!(matches!(
                put_static(&mut m, 10, mac, &StaticEntryInput { port: "Ethernet4".into() })
                    .unwrap_err(),
                WriteError::BadRequest(_)
            ));
        }
    }

    #[test]
    fn static_delete_finds_any_spelling() {
        let mut m = platform("202305.1");
        m.seed(CONFIG_DB, "FDB|Vlan10:AA:BB:CC:00:11:22", &[("port", "Ethernet4")]);
        delete_static(&mut m, 10, "aa:bb:cc:00:11:22").unwrap();
        assert!(!m.has_key(CONFIG_DB, "FDB|Vlan10:AA:BB:CC:00:11:22"));
        assert!(matches!(
            delete_static(&mut m, 10, "aa:bb:cc:00:11:22").unwrap_err(),
            WriteError::NotFound(_)
        ));
    }

    #[test]
    fn table_resolves_asic_entries_like_fdbshow() {
        let mut m = platform("202305.1");
        m.seed(
            COUNTERS_DB,
            "COUNTERS_PORT_NAME_MAP",
            &[("Ethernet4", "oid:0x1000000000002")],
        );
        m.seed(
            COUNTERS_DB,
            "COUNTERS_LAG_NAME_MAP",
            &[("PortChannel0001", "oid:0x2000000000fe0")],
        );
        m.seed(
            ASIC_DB,
            r#"ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:{"bvid":"oid:0x26000000000618","mac":"7C:FE:90:80:9F:05","switch_id":"oid:0x21000000000000"}"#,
            &[
                ("SAI_FDB_ENTRY_ATTR_TYPE", "SAI_FDB_ENTRY_TYPE_DYNAMIC"),
                ("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID", "oid:0x3a000000000619"),
            ],
        );
        m.seed(
            ASIC_DB,
            r#"ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:{"bvid":"oid:0x26000000000618","mac":"00:11:22:33:44:55","switch_id":"oid:0x21000000000000"}"#,
            &[
                ("SAI_FDB_ENTRY_ATTR_TYPE", "SAI_FDB_ENTRY_TYPE_STATIC"),
                ("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID", "oid:0x3a00000000061a"),
            ],
        );
        // A remnant entry whose bridge port no longer resolves is skipped.
        m.seed(
            ASIC_DB,
            r#"ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:{"bvid":"oid:0x26000000000618","mac":"de:ad:be:ef:00:01","switch_id":"oid:0x21000000000000"}"#,
            &[("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID", "oid:0x3a0000000000ff")],
        );
        m.seed(
            ASIC_DB,
            "ASIC_STATE:SAI_OBJECT_TYPE_BRIDGE_PORT:oid:0x3a000000000619",
            &[("SAI_BRIDGE_PORT_ATTR_PORT_ID", "oid:0x1000000000002")],
        );
        m.seed(
            ASIC_DB,
            "ASIC_STATE:SAI_OBJECT_TYPE_BRIDGE_PORT:oid:0x3a00000000061a",
            &[("SAI_BRIDGE_PORT_ATTR_PORT_ID", "oid:0x2000000000fe0")],
        );
        m.seed(
            ASIC_DB,
            "ASIC_STATE:SAI_OBJECT_TYPE_VLAN:oid:0x26000000000618",
            &[("SAI_VLAN_ATTR_VLAN_ID", "10")],
        );
        let doc = get_table(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["truncated"], false);
        assert_eq!(doc["total_entries"], 2);
        let entries = doc["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["mac"], "00:11:22:33:44:55");
        assert_eq!(entries[0]["port"], "PortChannel0001");
        assert_eq!(entries[0]["origin"], "static");
        assert_eq!(entries[1]["vlan_id"], 10);
        assert_eq!(entries[1]["mac"], "7c:fe:90:80:9f:05");
        assert_eq!(entries[1]["port"], "Ethernet4");
        assert_eq!(entries[1]["origin"], "dynamic");
    }

    #[test]
    fn asic_fdb_keys_parse_defensively() {
        assert_eq!(
            parse_asic_fdb_key(
                r#"ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:{"bvid":"oid:0x26","mac":"AA:BB:CC:00:11:22"}"#
            ),
            Some(("oid:0x26".to_string(), "aa:bb:cc:00:11:22".to_string()))
        );
        assert_eq!(parse_asic_fdb_key("ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:not json"), None);
        assert_eq!(parse_asic_fdb_key("ASIC_STATE:SAI_OBJECT_TYPE_VLAN:oid:0x26"), None);
    }
}
