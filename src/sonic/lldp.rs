//! LLDP for the console's Configure → Switching → LLDP page.
//!
//! Neighbors and the local chassis come from APPL_DB (`LLDP_ENTRY_TABLE:<ifname>`
//! and `LLDP_LOC_CHASSIS`, populated by lldp_syncd on every flavor). The
//! enabled flag is the FEATURE|lldp state, toggled through
//! `config feature state lldp …` — never a raw FEATURE write, so hostcfgd
//! starts/stops the container.
//!
//! Timers and the advertised system name are only configurable where a
//! management stack consumes the `LLDP|GLOBAL` CONFIG_DB table (Enterprise
//! SONiC); community's lldpmgrd ignores it, so those writes are rejected
//! with `timers_supported=false` explaining why.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, field, key_suffix, keys, row, Platform};
use super::switching::{natural_cmp, parse_num, WriteError, WriteResult};
use super::{APPL_DB, CONFIG_DB};

#[derive(Debug, Serialize)]
struct Neighbor {
    local_port: String,
    remote_system_name: Option<String>,
    remote_port_id: Option<String>,
    remote_port_description: Option<String>,
    remote_chassis_id: Option<String>,
    remote_system_description: Option<String>,
    remote_mgmt_addresses: Vec<String>,
    capabilities: Vec<String>,
}

/// Decode `lldp_rem_sys_cap_enabled` into labels. lldp_syncd publishes either
/// capability letters ("B, R") or the raw two-byte TLV bitmap as hex pairs
/// ("28 00", MSB-first per IEEE 802.1AB: other=0x80 … station=0x01).
pub fn decode_capabilities(v: &str) -> Vec<String> {
    const LABELS: [(&str, u8, char); 8] = [
        ("Other", 0x80, 'O'),
        ("Repeater", 0x40, 'P'),
        ("Bridge", 0x20, 'B'),
        ("WLAN Access Point", 0x10, 'W'),
        ("Router", 0x08, 'R'),
        ("Telephone", 0x04, 'T'),
        ("DOCSIS Cable Device", 0x02, 'D'),
        ("Station Only", 0x01, 'S'),
    ];
    let trimmed = v.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let hex_pairs: Vec<&str> = trimmed.split_whitespace().collect();
    let looks_hex = hex_pairs
        .iter()
        .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()));
    if looks_hex {
        let first = u8::from_str_radix(hex_pairs[0], 16).unwrap_or(0);
        return LABELS
            .iter()
            .filter(|(_, bit, _)| first & bit != 0)
            .map(|(label, _, _)| label.to_string())
            .collect();
    }
    // Letter form: "B, R" / "BR" / "B R".
    let mut out = Vec::new();
    for c in trimmed.chars().filter(|c| c.is_ascii_alphabetic()) {
        if let Some((label, _, _)) =
            LABELS.iter().find(|(_, _, letter)| *letter == c.to_ascii_uppercase())
        {
            if !out.contains(&label.to_string()) {
                out.push(label.to_string());
            }
        }
    }
    out
}

/// Split lldp's comma-joined management address list.
fn split_addrs(v: Option<&str>) -> Vec<String> {
    v.map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    if !p.lldp_supported() {
        return Ok(json!({
            "capability": Capability::no("the lldp feature is not present on this image"),
            "config": {
                "enabled": false, "hello_time": null, "multiplier": null,
                "system_name": null, "timers_supported": false,
            },
            "local": null,
            "neighbors": [],
        }));
    }
    let timers_supported = p.lldp_timers_supported();
    let global = if timers_supported {
        row(plat, CONFIG_DB, "LLDP|GLOBAL")
    } else {
        HashMap::new()
    };
    let config = json!({
        "enabled": p.feature_enabled("lldp"),
        "hello_time": if timers_supported { parse_num(field(&global, "hello_time")) } else { None },
        "multiplier": if timers_supported { parse_num(field(&global, "multiplier")) } else { None },
        "system_name": if timers_supported {
            field(&global, "system_name").map(str::to_string)
        } else {
            None
        },
        "timers_supported": timers_supported,
    });

    let loc = row(plat, APPL_DB, "LLDP_LOC_CHASSIS");
    let local = if loc.is_empty() {
        serde_json::Value::Null
    } else {
        json!({
            "chassis_id": field(&loc, "lldp_loc_chassis_id"),
            "system_name": field(&loc, "lldp_loc_sys_name"),
            "system_description": field(&loc, "lldp_loc_sys_desc"),
            "mgmt_addresses": split_addrs(field(&loc, "lldp_loc_man_addr")),
        })
    };

    let mut entries = keys(plat, APPL_DB, "LLDP_ENTRY_TABLE:*");
    entries.sort_by(|a, b| natural_cmp(a, b));
    let mut neighbors = Vec::with_capacity(entries.len());
    for key in entries {
        let Some(port) = key_suffix(&key, "LLDP_ENTRY_TABLE:") else { continue };
        let e = row(plat, APPL_DB, &key);
        if e.is_empty() {
            continue;
        }
        neighbors.push(Neighbor {
            local_port: port.to_string(),
            remote_system_name: field(&e, "lldp_rem_sys_name").map(str::to_string),
            remote_port_id: field(&e, "lldp_rem_port_id").map(str::to_string),
            remote_port_description: field(&e, "lldp_rem_port_desc").map(str::to_string),
            remote_chassis_id: field(&e, "lldp_rem_chassis_id").map(str::to_string),
            remote_system_description: field(&e, "lldp_rem_sys_desc").map(str::to_string),
            remote_mgmt_addresses: split_addrs(field(&e, "lldp_rem_man_addr")),
            capabilities: field(&e, "lldp_rem_sys_cap_enabled")
                .map(decode_capabilities)
                .unwrap_or_default(),
        });
    }

    Ok(json!({
        "capability": Capability::yes(),
        "config": config,
        "local": local,
        "neighbors": neighbors,
    }))
}

// ── PUT /api/switching/lldp/config ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ConfigInput {
    pub enabled: bool,
    pub hello_time: Option<u64>,
    pub multiplier: Option<u64>,
    pub system_name: Option<String>,
}

pub fn put_config(plat: &mut dyn Platform, input: &ConfigInput) -> WriteResult {
    let _lock = store::feature_lock("lldp");
    let p = probe::current(plat);
    if !p.lldp_supported() {
        return Err(WriteError::Conflict(
            "the lldp feature is not present on this image".to_string(),
        ));
    }
    let wants_timers =
        input.hello_time.is_some() || input.multiplier.is_some() || input.system_name.is_some();
    if wants_timers && !p.lldp_timers_supported() {
        return Err(WriteError::Unprocessable(
            "LLDP timers and system name are not configurable on community SONiC \
             (lldpmgrd does not consume the LLDP|GLOBAL table); only enable/disable is available"
                .to_string(),
        ));
    }
    if let Some(v) = input.hello_time {
        if !(5..=254).contains(&v) {
            return Err(WriteError::BadRequest(format!(
                "invalid hello_time {v} (must be 5-254)"
            )));
        }
    }
    if let Some(v) = input.multiplier {
        if !(1..=10).contains(&v) {
            return Err(WriteError::BadRequest(format!(
                "invalid multiplier {v} (must be 1-10)"
            )));
        }
    }

    // Toggle through the feature CLI so hostcfgd manages the container; a
    // raw FEATURE|lldp write would leave the daemon state behind.
    if input.enabled != p.feature_enabled("lldp") {
        let state = if input.enabled { "enabled" } else { "disabled" };
        let out = plat
            .run("config", &["feature", "state", "lldp", state])
            .map_err(|e| WriteError::Internal(format!("config feature state lldp: {e:#}")))?;
        if !out.ok {
            return Err(WriteError::Internal(format!(
                "config feature state lldp {state} failed: {}",
                out.stderr.trim()
            )));
        }
        probe::invalidate();
    }

    if p.lldp_timers_supported() {
        // Full desired document: absent optional fields clear their override.
        match input.hello_time {
            Some(v) => plat
                .hset(CONFIG_DB, "LLDP|GLOBAL", &[("hello_time", &v.to_string())])
                .map_err(WriteError::Redis)?,
            None => plat
                .hdel(CONFIG_DB, "LLDP|GLOBAL", &["hello_time"])
                .map_err(WriteError::Redis)?,
        }
        match input.multiplier {
            Some(v) => plat
                .hset(CONFIG_DB, "LLDP|GLOBAL", &[("multiplier", &v.to_string())])
                .map_err(WriteError::Redis)?,
            None => plat
                .hdel(CONFIG_DB, "LLDP|GLOBAL", &["multiplier"])
                .map_err(WriteError::Redis)?,
        }
        match &input.system_name {
            Some(v) => plat
                .hset(CONFIG_DB, "LLDP|GLOBAL", &[("system_name", v)])
                .map_err(WriteError::Redis)?,
            None => plat
                .hdel(CONFIG_DB, "LLDP|GLOBAL", &["system_name"])
                .map_err(WriteError::Redis)?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::*;

    fn community() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        m.seed(CONFIG_DB, "FEATURE|lldp", &[("state", "enabled")]);
        m
    }

    fn enterprise() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file(
            "/etc/sonic/sonic_version.yml",
            "build_version: '4.1.1'\nrelease: 'Enterprise SONiC'\n",
        );
        m.seed(CONFIG_DB, "FEATURE|lldp", &[("state", "enabled")]);
        m
    }

    #[test]
    fn decodes_capability_letters_and_bitmaps() {
        assert_eq!(decode_capabilities("B, R"), vec!["Bridge", "Router"]);
        assert_eq!(decode_capabilities("BR"), vec!["Bridge", "Router"]);
        // 0x28 = bridge + router in the MSB-first TLV byte.
        assert_eq!(decode_capabilities("28 00"), vec!["Bridge", "Router"]);
        assert_eq!(decode_capabilities("01 00"), vec!["Station Only"]);
        assert_eq!(decode_capabilities(""), Vec::<String>::new());
        assert_eq!(decode_capabilities("zz"), Vec::<String>::new());
    }

    #[test]
    fn community_reports_timers_unsupported_and_reads_neighbors() {
        let mut m = community();
        // A stray LLDP|GLOBAL row (written by other tooling) must not leak
        // into the community response — nothing consumes it.
        m.seed(CONFIG_DB, "LLDP|GLOBAL", &[("hello_time", "10")]);
        m.seed(
            APPL_DB,
            "LLDP_ENTRY_TABLE:Ethernet0",
            &[
                ("lldp_rem_sys_name", "spine1"),
                ("lldp_rem_port_id", "Ethernet12"),
                ("lldp_rem_chassis_id", "aa:bb:cc:dd:ee:ff"),
                ("lldp_rem_man_addr", "10.0.0.1,fe80::1"),
                ("lldp_rem_sys_cap_enabled", "28 00"),
            ],
        );
        m.seed(
            APPL_DB,
            "LLDP_LOC_CHASSIS",
            &[("lldp_loc_chassis_id", "11:22:33:44:55:66"), ("lldp_loc_sys_name", "leaf1")],
        );
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["config"]["enabled"], true);
        assert_eq!(doc["config"]["timers_supported"], false);
        assert_eq!(doc["config"]["hello_time"], serde_json::Value::Null);
        assert_eq!(doc["local"]["system_name"], "leaf1");
        let n = &doc["neighbors"][0];
        assert_eq!(n["local_port"], "Ethernet0");
        assert_eq!(n["remote_system_name"], "spine1");
        assert_eq!(n["remote_mgmt_addresses"], serde_json::json!(["10.0.0.1", "fe80::1"]));
        assert_eq!(n["capabilities"], serde_json::json!(["Bridge", "Router"]));
    }

    #[test]
    fn community_rejects_timer_writes_with_clear_error() {
        let mut m = community();
        let err = put_config(
            &mut m,
            &ConfigInput {
                enabled: true,
                hello_time: Some(30),
                multiplier: None,
                system_name: None,
            },
        )
        .unwrap_err();
        match err {
            WriteError::Unprocessable(msg) => assert!(msg.contains("community"), "{msg}"),
            other => panic!("expected Unprocessable, got {other:?}"),
        }
        // Enable/disable alone is fine and goes through the feature CLI.
        put_config(
            &mut m,
            &ConfigInput { enabled: false, hello_time: None, multiplier: None, system_name: None },
        )
        .unwrap();
        assert!(m.log.iter().any(|l| l == "RUN config feature state lldp disabled"), "{:?}", m.log);
    }

    #[test]
    fn enterprise_writes_lldp_global() {
        let mut m = enterprise();
        put_config(
            &mut m,
            &ConfigInput {
                enabled: true,
                hello_time: Some(30),
                multiplier: Some(4),
                system_name: Some("core1".to_string()),
            },
        )
        .unwrap();
        let row = m.row(CONFIG_DB, "LLDP|GLOBAL");
        assert_eq!(row.get("hello_time").unwrap(), "30");
        assert_eq!(row.get("multiplier").unwrap(), "4");
        assert_eq!(row.get("system_name").unwrap(), "core1");
        // No feature toggle ran — lldp was already enabled.
        assert!(!m.log.iter().any(|l| l.starts_with("RUN config feature")), "{:?}", m.log);
        // Absent fields clear their override on the next full-document PUT.
        put_config(
            &mut m,
            &ConfigInput { enabled: true, hello_time: None, multiplier: None, system_name: None },
        )
        .unwrap();
        assert!(!m.has_key(CONFIG_DB, "LLDP|GLOBAL"));
    }

    #[test]
    fn timer_ranges_validated() {
        let mut m = enterprise();
        for (hello, mult) in [(Some(4), None), (Some(255), None), (None, Some(0)), (None, Some(11))]
        {
            let err = put_config(
                &mut m,
                &ConfigInput {
                    enabled: true,
                    hello_time: hello,
                    multiplier: mult,
                    system_name: None,
                },
            )
            .unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{hello:?}/{mult:?}");
        }
    }
}
