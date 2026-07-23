//! Per-port storm control for the console's Configure → Switching → Storm
//! Control page.
//!
//! Backed by CONFIG_DB `PORT_STORM_CONTROL|<port>|<class>` rows (classes
//! broadcast / unknown-unicast / unknown-multicast, single field `kbps`).
//! Community orchagent handles the table since 202205; older community
//! images report unsupported so limits never sit inert in CONFIG_DB.

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, field, key_suffix, keys, row, Platform};
use super::switching::{natural_cmp, parse_num, WriteError, WriteResult};
use super::CONFIG_DB;

const UNSUPPORTED: &str =
    "Storm control requires an image whose orchagent handles PORT_STORM_CONTROL \
     (community SONiC 202205 or newer).";

/// The three traffic classes, with their CONFIG_DB key spelling.
const CLASSES: [(&str, &str); 3] = [
    ("broadcast_kbps", "broadcast"),
    ("unknown_unicast_kbps", "unknown-unicast"),
    ("unknown_multicast_kbps", "unknown-multicast"),
];

#[derive(Debug, Serialize)]
struct PortDoc {
    port: String,
    alias: Option<String>,
    broadcast_kbps: Option<u64>,
    unknown_unicast_kbps: Option<u64>,
    unknown_multicast_kbps: Option<u64>,
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    if !p.storm_control_supported() {
        return Ok(json!({ "capability": Capability::no(UNSUPPORTED), "ports": [] }));
    }

    // One row per front-panel port, limits configured or not.
    let mut names: Vec<String> = keys(plat, CONFIG_DB, "PORT|*")
        .iter()
        .filter_map(|k| key_suffix(k, "PORT|"))
        .map(str::to_string)
        .collect();
    names.sort_by(|a, b| natural_cmp(a, b));
    let mut ports = Vec::with_capacity(names.len());
    for name in names {
        let alias = field(&row(plat, CONFIG_DB, &format!("PORT|{name}")), "alias")
            .map(str::to_string);
        let kbps = |plat: &mut dyn Platform, class: &str| {
            parse_num(field(
                &row(plat, CONFIG_DB, &format!("PORT_STORM_CONTROL|{name}|{class}")),
                "kbps",
            ))
        };
        ports.push(PortDoc {
            broadcast_kbps: kbps(plat, "broadcast"),
            unknown_unicast_kbps: kbps(plat, "unknown-unicast"),
            unknown_multicast_kbps: kbps(plat, "unknown-multicast"),
            port: name,
            alias,
        });
    }

    Ok(json!({ "capability": Capability::yes(), "ports": ports }))
}

// ── PUT /api/switching/storm-control/{port} ─────────────────────────────────

/// Full desired limits for one port; null removes that class's row.
#[derive(Debug, Deserialize)]
pub struct PortInput {
    pub broadcast_kbps: Option<u64>,
    pub unknown_unicast_kbps: Option<u64>,
    pub unknown_multicast_kbps: Option<u64>,
}

impl PortInput {
    fn limit(&self, json_name: &str) -> Option<u64> {
        match json_name {
            "broadcast_kbps" => self.broadcast_kbps,
            "unknown_unicast_kbps" => self.unknown_unicast_kbps,
            _ => self.unknown_multicast_kbps,
        }
    }
}

pub fn put_port(plat: &mut dyn Platform, port: &str, input: &PortInput) -> WriteResult {
    let _lock = store::feature_lock("storm-control");
    for (json_name, _) in CLASSES {
        if let Some(v) = input.limit(json_name) {
            // 400G is the fastest front panel any supported platform ships.
            if v == 0 || v > 400_000_000 {
                return Err(WriteError::BadRequest(format!(
                    "invalid {json_name} {v} (must be 1-400000000; use null to remove the limit)"
                )));
            }
        }
    }
    let p = probe::current(plat);
    if !p.storm_control_supported() {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    if !plat.exists(CONFIG_DB, &format!("PORT|{port}"))? {
        return Err(WriteError::NotFound(format!("no such port {port}")));
    }

    for (json_name, class) in CLASSES {
        let key = format!("PORT_STORM_CONTROL|{port}|{class}");
        match input.limit(json_name) {
            Some(v) => plat.hset(CONFIG_DB, &key, &[("kbps", &v.to_string())])?,
            None => plat.del(CONFIG_DB, &key)?,
        }
    }
    Ok(())
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
        m.seed(CONFIG_DB, "PORT|Ethernet0", &[("alias", "Eth1/1")]);
        m.seed(CONFIG_DB, "PORT|Ethernet4", &[("alias", "Eth1/2")]);
        m
    }

    #[test]
    fn old_community_is_unsupported() {
        let mut m = platform("202111.3");
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        assert_eq!(doc["capability"]["reason"], UNSUPPORTED);
        assert_eq!(doc["ports"], json!([]));
        let err = put_port(
            &mut m,
            "Ethernet0",
            &PortInput {
                broadcast_kbps: Some(1000),
                unknown_unicast_kbps: None,
                unknown_multicast_kbps: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
        assert!(!m.has_key(CONFIG_DB, "PORT_STORM_CONTROL|Ethernet0|broadcast"));
    }

    #[test]
    fn get_lists_every_port_with_limits() {
        let mut m = platform("202205.7");
        m.seed(CONFIG_DB, "PORT_STORM_CONTROL|Ethernet0|broadcast", &[("kbps", "10000")]);
        m.seed(
            CONFIG_DB,
            "PORT_STORM_CONTROL|Ethernet0|unknown-multicast",
            &[("kbps", "5000")],
        );
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        let ports = doc["ports"].as_array().unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0]["port"], "Ethernet0");
        assert_eq!(ports[0]["alias"], "Eth1/1");
        assert_eq!(ports[0]["broadcast_kbps"], 10000);
        assert_eq!(ports[0]["unknown_unicast_kbps"], serde_json::Value::Null);
        assert_eq!(ports[0]["unknown_multicast_kbps"], 5000);
        // Ethernet4 has no limits but still appears.
        assert_eq!(ports[1]["port"], "Ethernet4");
        assert_eq!(ports[1]["broadcast_kbps"], serde_json::Value::Null);
    }

    #[test]
    fn put_writes_and_clears_per_class_rows() {
        let mut m = platform("202305.1");
        m.seed(CONFIG_DB, "PORT_STORM_CONTROL|Ethernet0|unknown-unicast", &[("kbps", "77")]);
        put_port(
            &mut m,
            "Ethernet0",
            &PortInput {
                broadcast_kbps: Some(20000),
                unknown_unicast_kbps: None,
                unknown_multicast_kbps: Some(4000),
            },
        )
        .unwrap();
        assert_eq!(
            m.row(CONFIG_DB, "PORT_STORM_CONTROL|Ethernet0|broadcast").get("kbps").unwrap(),
            "20000"
        );
        // null cleared the previously configured class.
        assert!(!m.has_key(CONFIG_DB, "PORT_STORM_CONTROL|Ethernet0|unknown-unicast"));
        assert_eq!(
            m.row(CONFIG_DB, "PORT_STORM_CONTROL|Ethernet0|unknown-multicast")
                .get("kbps")
                .unwrap(),
            "4000"
        );
    }

    #[test]
    fn put_validates_port_and_values() {
        let mut m = platform("202305.1");
        let input = PortInput {
            broadcast_kbps: Some(0),
            unknown_unicast_kbps: None,
            unknown_multicast_kbps: None,
        };
        assert!(matches!(
            put_port(&mut m, "Ethernet0", &input).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        let ok = PortInput {
            broadcast_kbps: Some(1000),
            unknown_unicast_kbps: None,
            unknown_multicast_kbps: None,
        };
        assert!(matches!(
            put_port(&mut m, "Ethernet99", &ok).unwrap_err(),
            WriteError::NotFound(_)
        ));
    }
}
