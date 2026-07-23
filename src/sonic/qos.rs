//! QoS classification, phase 1: trust mode + DSCP→TC maps, for the console's
//! Configure → QoS page.
//!
//! Backed by CONFIG_DB `DSCP_TO_TC_MAP` objects (field name = DSCP, value =
//! traffic class) and each port's `PORT_QOS_MAP` row: a bound
//! `dscp_to_tc_map` means the port trusts DSCP, no binding means trust
//! "none". Queues, scheduling, PFC/ECN, and dot1p trust are a later phase.
//! qosorch consumes these tables on every image, so the capability is always
//! supported. Older images stored map references in `[DSCP_TO_TC_MAP|name]`
//! ABNF form — reads tolerate both, writes use the plain name.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::Capability;
use super::store::{self, field, key_suffix, keys, row, Platform};
use super::switching::{WriteError, WriteResult};
use super::CONFIG_DB;

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

/// The map name out of a PORT_QOS_MAP reference, either syntax. Pure.
pub fn map_ref_name(v: &str) -> &str {
    v.strip_prefix("[DSCP_TO_TC_MAP|").and_then(|s| s.strip_suffix(']')).unwrap_or(v)
}

/// "Ethernet10" sorts after "Ethernet2" — split at the first digit.
fn natural_key(name: &str) -> (String, u64) {
    let at = name.find(|c: char| c.is_ascii_digit()).unwrap_or(name.len());
    (name[..at].to_string(), name[at..].parse().unwrap_or(0))
}

// ── GET /api/qos ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct EntryDoc {
    dscp: u32,
    tc: u32,
}

#[derive(Debug, Serialize)]
struct MapDoc {
    name: String,
    entries: Vec<EntryDoc>,
    bound_ports: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PortDoc {
    name: String,
    alias: Option<String>,
    trust: &'static str,
    dscp_to_tc_map: Option<String>,
}

/// Every port's map binding (port → map name), both reference syntaxes.
fn bindings(plat: &mut dyn Platform) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for key in keys(plat, CONFIG_DB, "PORT_QOS_MAP|*") {
        let Some(port) = key_suffix(&key, "PORT_QOS_MAP|") else { continue };
        let port = port.to_string();
        if let Some(m) = field(&row(plat, CONFIG_DB, &key), "dscp_to_tc_map") {
            out.insert(port, map_ref_name(m).to_string());
        }
    }
    out
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let bound = bindings(plat);

    let mut maps = Vec::new();
    for key in keys(plat, CONFIG_DB, "DSCP_TO_TC_MAP|*") {
        let Some(name) = key_suffix(&key, "DSCP_TO_TC_MAP|") else { continue };
        let name = name.to_string();
        let cfg = row(plat, CONFIG_DB, &key);
        let mut entries: Vec<(u32, u32)> = cfg
            .iter()
            .filter_map(|(d, t)| Some((d.trim().parse().ok()?, t.trim().parse().ok()?)))
            .collect();
        entries.sort();
        let mut bound_ports: Vec<String> =
            bound.iter().filter(|(_, m)| **m == name).map(|(p, _)| p.clone()).collect();
        bound_ports.sort_by_key(|p| natural_key(p));
        maps.push(MapDoc {
            name,
            entries: entries.into_iter().map(|(dscp, tc)| EntryDoc { dscp, tc }).collect(),
            bound_ports,
        });
    }
    maps.sort_by(|a, b| a.name.cmp(&b.name));

    let mut ports = Vec::new();
    for key in keys(plat, CONFIG_DB, "PORT|*") {
        let Some(name) = key_suffix(&key, "PORT|") else { continue };
        let name = name.to_string();
        let cfg = row(plat, CONFIG_DB, &key);
        let map = bound.get(&name).cloned();
        ports.push(PortDoc {
            alias: field(&cfg, "alias").map(str::to_string),
            trust: if map.is_some() { "dscp" } else { "none" },
            dscp_to_tc_map: map,
            name,
        });
    }
    ports.sort_by_key(|p| natural_key(&p.name));

    // DSCP_TO_TC_MAP / PORT_QOS_MAP are core SONiC — always supported.
    Ok(json!({ "capability": Capability::yes(), "dscp_tc_maps": maps, "ports": ports }))
}

// ── PUT /api/qos/dscp-maps/{name} ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EntryInput {
    pub dscp: u32,
    pub tc: u32,
}

/// The full desired map — a PUT replaces the DSCP_TO_TC_MAP object.
#[derive(Debug, Deserialize)]
pub struct MapInput {
    pub entries: Vec<EntryInput>,
}

fn check_map_name(name: &str) -> WriteResult {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(bad(format!("invalid DSCP map name {name:?}")))
    }
}

pub fn put_dscp_map(plat: &mut dyn Platform, name: &str, input: &MapInput) -> WriteResult {
    let _lock = store::feature_lock("qos");
    check_map_name(name)?;
    if input.entries.is_empty() {
        return Err(bad("a DSCP map needs at least one entry"));
    }
    let mut seen = BTreeSet::new();
    for e in &input.entries {
        if e.dscp > 63 {
            return Err(bad(format!("invalid dscp {} (must be 0-63)", e.dscp)));
        }
        if e.tc > 7 {
            return Err(bad(format!("invalid tc {} (must be 0-7)", e.tc)));
        }
        if !seen.insert(e.dscp) {
            return Err(bad(format!("dscp {} appears twice", e.dscp)));
        }
    }
    // Replace the whole object so dropped code points never linger.
    let key = format!("DSCP_TO_TC_MAP|{name}");
    plat.del(CONFIG_DB, &key)?;
    let fields: Vec<(String, String)> =
        input.entries.iter().map(|e| (e.dscp.to_string(), e.tc.to_string())).collect();
    let refs: Vec<(&str, &str)> = fields.iter().map(|(f, v)| (f.as_str(), v.as_str())).collect();
    plat.hset(CONFIG_DB, &key, &refs)?;
    Ok(())
}

// ── DELETE /api/qos/dscp-maps/{name} ────────────────────────────────────────

pub fn delete_dscp_map(plat: &mut dyn Platform, name: &str) -> WriteResult {
    let _lock = store::feature_lock("qos");
    let key = format!("DSCP_TO_TC_MAP|{name}");
    if !plat.exists(CONFIG_DB, &key)? {
        return Err(WriteError::NotFound(format!("no such DSCP map {name}")));
    }
    let mut bound: Vec<String> = bindings(plat)
        .into_iter()
        .filter(|(_, m)| m == name)
        .map(|(p, _)| p)
        .collect();
    if !bound.is_empty() {
        bound.sort_by_key(|p| natural_key(p));
        return Err(WriteError::Conflict(format!(
            "DSCP map {name} is bound to port(s) {}; set their trust to none first",
            bound.join(", ")
        )));
    }
    plat.del(CONFIG_DB, &key)?;
    Ok(())
}

// ── PUT /api/qos/ports/{port} ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustMode {
    Dscp,
    None,
}

#[derive(Debug, Deserialize)]
pub struct PortInput {
    pub trust: TrustMode,
    pub dscp_to_tc_map: Option<String>,
}

pub fn put_port(plat: &mut dyn Platform, port: &str, input: &PortInput) -> WriteResult {
    let _lock = store::feature_lock("qos");
    if !plat.exists(CONFIG_DB, &format!("PORT|{port}"))? {
        return Err(WriteError::NotFound(format!("no such port {port}")));
    }
    let key = format!("PORT_QOS_MAP|{port}");
    match input.trust {
        TrustMode::Dscp => {
            let Some(map) = input.dscp_to_tc_map.as_deref().filter(|m| !m.is_empty()) else {
                return Err(bad("trust \"dscp\" requires dscp_to_tc_map"));
            };
            if !plat.exists(CONFIG_DB, &format!("DSCP_TO_TC_MAP|{map}"))? {
                return Err(bad(format!("no such DSCP map {map}")));
            }
            plat.hset(CONFIG_DB, &key, &[("dscp_to_tc_map", map)])?;
        }
        TrustMode::None => {
            if input.dscp_to_tc_map.is_some() {
                return Err(bad("trust \"none\" does not take a dscp_to_tc_map"));
            }
            // Only the binding goes; other PORT_QOS_MAP fields (a later QoS
            // phase's) stay, and redis drops the row once its last field is
            // deleted.
            plat.hdel(CONFIG_DB, &key, &["dscp_to_tc_map"])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::*;

    fn platform() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed(CONFIG_DB, "PORT|Ethernet0", &[("alias", "Eth1/1")]);
        m.seed(CONFIG_DB, "PORT|Ethernet4", &[("alias", "Eth1/2")]);
        m.seed(CONFIG_DB, "PORT|Ethernet16", &[("NULL", "NULL")]);
        m
    }

    fn azure() -> MapInput {
        MapInput {
            entries: vec![EntryInput { dscp: 46, tc: 5 }, EntryInput { dscp: 0, tc: 0 }],
        }
    }

    #[test]
    fn get_maps_and_ports() {
        let mut m = platform();
        put_dscp_map(&mut m, "AZURE", &azure()).unwrap();
        put_port(
            &mut m,
            "Ethernet0",
            &PortInput { trust: TrustMode::Dscp, dscp_to_tc_map: Some("AZURE".into()) },
        )
        .unwrap();
        // A row bound the old ABNF way still counts.
        m.seed(
            CONFIG_DB,
            "PORT_QOS_MAP|Ethernet16",
            &[("dscp_to_tc_map", "[DSCP_TO_TC_MAP|AZURE]")],
        );
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        let maps = doc["dscp_tc_maps"].as_array().unwrap();
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0]["name"], "AZURE");
        assert_eq!(maps[0]["entries"], json!([{ "dscp": 0, "tc": 0 }, { "dscp": 46, "tc": 5 }]));
        assert_eq!(maps[0]["bound_ports"], json!(["Ethernet0", "Ethernet16"]));
        let ports = doc["ports"].as_array().unwrap();
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0]["name"], "Ethernet0");
        assert_eq!(ports[0]["alias"], "Eth1/1");
        assert_eq!(ports[0]["trust"], "dscp");
        assert_eq!(ports[0]["dscp_to_tc_map"], "AZURE");
        assert_eq!(ports[1]["name"], "Ethernet4");
        assert_eq!(ports[1]["alias"], "Eth1/2");
        assert_eq!(ports[1]["trust"], "none");
        assert_eq!(ports[1]["dscp_to_tc_map"], serde_json::Value::Null);
        // Natural sort: Ethernet16 after Ethernet4, alias null when unset.
        assert_eq!(ports[2]["name"], "Ethernet16");
        assert_eq!(ports[2]["alias"], serde_json::Value::Null);
    }

    #[test]
    fn put_map_replaces_object() {
        let mut m = platform();
        put_dscp_map(&mut m, "AZURE", &azure()).unwrap();
        let row = m.row(CONFIG_DB, "DSCP_TO_TC_MAP|AZURE");
        assert_eq!(row.get("46").unwrap(), "5");
        assert_eq!(row.get("0").unwrap(), "0");
        put_dscp_map(
            &mut m,
            "AZURE",
            &MapInput { entries: vec![EntryInput { dscp: 8, tc: 1 }] },
        )
        .unwrap();
        let row = m.row(CONFIG_DB, "DSCP_TO_TC_MAP|AZURE");
        assert_eq!(row.get("8").unwrap(), "1");
        assert!(!row.contains_key("46"), "stale code point survived the replace");
    }

    #[test]
    fn put_map_validation() {
        let mut m = platform();
        for entries in [
            vec![],
            vec![EntryInput { dscp: 64, tc: 0 }],
            vec![EntryInput { dscp: 0, tc: 8 }],
            vec![EntryInput { dscp: 5, tc: 1 }, EntryInput { dscp: 5, tc: 2 }],
        ] {
            let err = put_dscp_map(&mut m, "M", &MapInput { entries }).unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{err:?}");
        }
        let err = put_dscp_map(&mut m, "bad|name", &azure()).unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
    }

    #[test]
    fn delete_map_guarded_by_bindings() {
        let mut m = platform();
        put_dscp_map(&mut m, "AZURE", &azure()).unwrap();
        put_port(
            &mut m,
            "Ethernet0",
            &PortInput { trust: TrustMode::Dscp, dscp_to_tc_map: Some("AZURE".into()) },
        )
        .unwrap();
        let err = delete_dscp_map(&mut m, "AZURE").unwrap_err();
        match err {
            WriteError::Conflict(msg) => assert!(msg.contains("Ethernet0"), "{msg}"),
            other => panic!("expected Conflict, got {other:?}"),
        }
        put_port(&mut m, "Ethernet0", &PortInput { trust: TrustMode::None, dscp_to_tc_map: None })
            .unwrap();
        delete_dscp_map(&mut m, "AZURE").unwrap();
        assert!(!m.has_key(CONFIG_DB, "DSCP_TO_TC_MAP|AZURE"));
        assert!(matches!(delete_dscp_map(&mut m, "AZURE").unwrap_err(), WriteError::NotFound(_)));
    }

    #[test]
    fn port_trust_binds_and_clears() {
        let mut m = platform();
        put_dscp_map(&mut m, "AZURE", &azure()).unwrap();
        // Other PORT_QOS_MAP fields survive a trust change.
        m.seed(CONFIG_DB, "PORT_QOS_MAP|Ethernet0", &[("pfc_enable", "3,4")]);
        put_port(
            &mut m,
            "Ethernet0",
            &PortInput { trust: TrustMode::Dscp, dscp_to_tc_map: Some("AZURE".into()) },
        )
        .unwrap();
        assert_eq!(
            m.row(CONFIG_DB, "PORT_QOS_MAP|Ethernet0").get("dscp_to_tc_map").unwrap(),
            "AZURE"
        );
        put_port(&mut m, "Ethernet0", &PortInput { trust: TrustMode::None, dscp_to_tc_map: None })
            .unwrap();
        let row = m.row(CONFIG_DB, "PORT_QOS_MAP|Ethernet0");
        assert!(!row.contains_key("dscp_to_tc_map"));
        assert_eq!(row.get("pfc_enable").unwrap(), "3,4");
    }

    #[test]
    fn port_put_validation() {
        let mut m = platform();
        put_dscp_map(&mut m, "AZURE", &azure()).unwrap();
        assert!(matches!(
            put_port(
                &mut m,
                "Ethernet99",
                &PortInput { trust: TrustMode::Dscp, dscp_to_tc_map: Some("AZURE".into()) },
            )
            .unwrap_err(),
            WriteError::NotFound(_)
        ));
        assert!(matches!(
            put_port(
                &mut m,
                "Ethernet0",
                &PortInput { trust: TrustMode::Dscp, dscp_to_tc_map: None },
            )
            .unwrap_err(),
            WriteError::BadRequest(_)
        ));
        assert!(matches!(
            put_port(
                &mut m,
                "Ethernet0",
                &PortInput { trust: TrustMode::Dscp, dscp_to_tc_map: Some("NOPE".into()) },
            )
            .unwrap_err(),
            WriteError::BadRequest(_)
        ));
        assert!(matches!(
            put_port(
                &mut m,
                "Ethernet0",
                &PortInput { trust: TrustMode::None, dscp_to_tc_map: Some("AZURE".into()) },
            )
            .unwrap_err(),
            WriteError::BadRequest(_)
        ));
    }
}
