//! DHCP relay for the console's Configure → Routing → DHCP Relay page — the
//! relay-centric view of the per-VLAN `dhcp_servers` list in the CONFIG_DB
//! VLAN table, the same field the VLAN editor writes as `dhcp_helpers`.
//!
//! The write path is deliberately byte-identical to
//! [`super::switching::update_vlan`]'s dhcp_helpers handling (comma-joined
//! `dhcp_servers@`, both field spellings dropped when the list empties, no
//! service kick) so the two pages can never fight over the field.

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, field, key_suffix, keys, row, two_parts, Platform};
use super::switching::{dhcp_helpers, parse_num, vlan_id_from_name, WriteError, WriteResult};
use super::CONFIG_DB;

const UNSUPPORTED: &str = "the dhcp_relay feature is not present on this image";

#[derive(Debug, Serialize)]
struct VlanDoc {
    vlan_id: u32,
    description: Option<String>,
    ip_addresses: Vec<String>,
    servers: Vec<String>,
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    if !p.dhcp_relay_supported() {
        return Ok(json!({ "capability": Capability::no(UNSUPPORTED), "vlans": [] }));
    }

    // Every configured VLAN appears, relaying or not — the page shows the
    // whole switch's relay posture.
    let mut vlans = Vec::new();
    for key in keys(plat, CONFIG_DB, "VLAN|*") {
        let Some(name) = key_suffix(&key, "VLAN|") else { continue };
        let r = row(plat, CONFIG_DB, &key);
        let Some(vlan_id) = parse_num(field(&r, "vlanid"))
            .and_then(|n| u32::try_from(n).ok())
            .or_else(|| vlan_id_from_name(name))
        else {
            continue;
        };
        // Only three-part VLAN_INTERFACE|VlanN|<cidr> keys carry addresses.
        let mut ip_addresses: Vec<String> = keys(plat, CONFIG_DB, &format!("VLAN_INTERFACE|{name}|*"))
            .iter()
            .filter_map(|k| two_parts(k, "VLAN_INTERFACE|"))
            .map(|(_, cidr)| cidr.to_string())
            .collect();
        ip_addresses.sort();
        vlans.push(VlanDoc {
            vlan_id,
            description: field(&r, "description").map(str::to_string),
            ip_addresses,
            servers: dhcp_helpers(&r),
        });
    }
    vlans.sort_by_key(|v| v.vlan_id);

    Ok(json!({ "capability": Capability::yes(), "vlans": vlans }))
}

// ── PUT /api/routing/dhcp-relay/{vlan_id} ───────────────────────────────────

/// The full desired server set; empty = relay off for the VLAN.
#[derive(Debug, Deserialize)]
pub struct VlanInput {
    pub servers: Vec<String>,
}

pub fn put_vlan(plat: &mut dyn Platform, vlan_id: u32, input: &VlanInput) -> WriteResult {
    let _lock = store::feature_lock("dhcp-relay");
    let mut seen = Vec::new();
    for s in &input.servers {
        if s.parse::<std::net::IpAddr>().is_err() {
            return Err(WriteError::BadRequest(format!(
                "invalid DHCP server address {s:?} (expected an IP address)"
            )));
        }
        if seen.contains(&s) {
            return Err(WriteError::BadRequest(format!("duplicate DHCP server {s}")));
        }
        seen.push(s);
    }
    let p = probe::current(plat);
    if !p.dhcp_relay_supported() {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    let key = format!("VLAN|Vlan{vlan_id}");
    if !plat.exists(CONFIG_DB, &key)? {
        return Err(WriteError::NotFound(format!("no such VLAN Vlan{vlan_id}")));
    }

    if input.servers.is_empty() {
        // Both spellings go, exactly as the VLAN endpoint clears them, so
        // the reader can't fall back to a stale list.
        plat.hdel(CONFIG_DB, &key, &["dhcp_servers@"])?;
        plat.hdel(CONFIG_DB, &key, &["dhcp_servers"])?;
    } else {
        plat.hset(CONFIG_DB, &key, &[("dhcp_servers@", input.servers.join(",").as_str())])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::*;

    fn platform() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        m.seed(CONFIG_DB, "FEATURE|dhcp_relay", &[("state", "enabled")]);
        m.seed(
            CONFIG_DB,
            "VLAN|Vlan10",
            &[("vlanid", "10"), ("description", "servers"), ("dhcp_servers@", "10.0.0.10,10.0.0.11")],
        );
        m.seed(CONFIG_DB, "VLAN|Vlan20", &[("vlanid", "20")]);
        m.seed(CONFIG_DB, "VLAN_INTERFACE|Vlan10", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "VLAN_INTERFACE|Vlan10|10.0.10.1/24", &[("NULL", "NULL")]);
        m
    }

    #[test]
    fn missing_feature_is_unsupported() {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        m.seed(CONFIG_DB, "VLAN|Vlan10", &[("vlanid", "10")]);
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        assert_eq!(doc["capability"]["reason"], UNSUPPORTED);
        assert_eq!(doc["vlans"], json!([]));
        let err = put_vlan(&mut m, 10, &VlanInput { servers: vec!["10.0.0.10".into()] })
            .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
    }

    #[test]
    fn get_lists_every_vlan_with_relay_state() {
        let mut m = platform();
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        let vlans = doc["vlans"].as_array().unwrap();
        assert_eq!(vlans.len(), 2);
        assert_eq!(vlans[0]["vlan_id"], 10);
        assert_eq!(vlans[0]["description"], "servers");
        assert_eq!(vlans[0]["ip_addresses"], json!(["10.0.10.1/24"]));
        assert_eq!(vlans[0]["servers"], json!(["10.0.0.10", "10.0.0.11"]));
        // Vlan20 relays nothing but still appears.
        assert_eq!(vlans[1]["vlan_id"], 20);
        assert_eq!(vlans[1]["description"], serde_json::Value::Null);
        assert_eq!(vlans[1]["servers"], json!([]));
    }

    #[test]
    fn put_writes_the_same_field_as_the_vlan_endpoint() {
        let mut m = platform();
        put_vlan(&mut m, 20, &VlanInput { servers: vec!["10.0.0.10".into(), "fc00::5".into()] })
            .unwrap();
        assert_eq!(
            m.row(CONFIG_DB, "VLAN|Vlan20").get("dhcp_servers@").unwrap(),
            "10.0.0.10,fc00::5"
        );
    }

    #[test]
    fn empty_set_clears_both_field_spellings() {
        let mut m = platform();
        // A stale plain-name variant written by other tooling goes too.
        m.seed(CONFIG_DB, "VLAN|Vlan10", &[("dhcp_servers", "10.9.9.9")]);
        put_vlan(&mut m, 10, &VlanInput { servers: vec![] }).unwrap();
        let row = m.row(CONFIG_DB, "VLAN|Vlan10");
        assert!(!row.contains_key("dhcp_servers@"));
        assert!(!row.contains_key("dhcp_servers"));
        // The VLAN row itself survives.
        assert_eq!(row.get("vlanid").unwrap(), "10");
    }

    #[test]
    fn put_validates_servers_and_vlan() {
        let mut m = platform();
        assert!(matches!(
            put_vlan(&mut m, 10, &VlanInput { servers: vec!["not-an-ip".into()] }).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        assert!(matches!(
            put_vlan(
                &mut m,
                10,
                &VlanInput { servers: vec!["10.0.0.10".into(), "10.0.0.10".into()] },
            )
            .unwrap_err(),
            WriteError::BadRequest(_)
        ));
        assert!(matches!(
            put_vlan(&mut m, 99, &VlanInput { servers: vec!["10.0.0.10".into()] }).unwrap_err(),
            WriteError::NotFound(_)
        ));
    }
}
