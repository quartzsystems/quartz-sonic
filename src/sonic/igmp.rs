//! IGMP snooping for the console's Configure → Switching → IGMP Snooping
//! page.
//!
//! Community SONiC has no L2 multicast snooping — the L2MC HLD never merged —
//! so on community images the endpoint reports `capability.supported=false`
//! with empty lists and every write is refused. On Enterprise SONiC
//! (Dell/Broadcom) snooping is configured through the vendor's L2MC tables:
//! CONFIG_DB `CFG_L2MC_TABLE|Vlan<id>` (enabled, querier, fast-leave,
//! version, query-interval, last-member-query-interval,
//! query-max-response-time — hyphenated field names, "true"/"false" strings)
//! with learned/static groups published to APPL_DB
//! `APP_L2MC_MEMBER_TABLE:Vlan<id>:<group>[:<source>]` (ports@ list, type
//! static|dynamic). The mapping is contained in this module so vendor schema
//! drift stays here.

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, field, keys, row, Platform};
use super::switching::{key_id_sorted_vlans, parse_bool, parse_num, WriteError, WriteResult};
use super::{APPL_DB, CONFIG_DB};

const UNSUPPORTED: &str = "IGMP snooping requires Enterprise SONiC.";

#[derive(Debug, Serialize)]
struct VlanDoc {
    vlan_id: u32,
    enabled: bool,
    querier: bool,
    fast_leave: bool,
    version: Option<u32>,
    query_interval: Option<u64>,
    last_member_query_interval: Option<u64>,
    query_max_response_time: Option<u64>,
}

#[derive(Debug, Serialize)]
struct GroupDoc {
    vlan_id: u32,
    group_address: String,
    source_address: Option<String>,
    ports: Vec<String>,
    origin: &'static str,
}

/// Parse an APP_L2MC_MEMBER_TABLE key's Vlan/group/source parts. Pure.
pub fn parse_group_key(key: &str) -> Option<(u32, String, Option<String>)> {
    let rest = key.strip_prefix("APP_L2MC_MEMBER_TABLE:")?;
    let mut parts = rest.split(':');
    let vlan = super::switching::vlan_id_from_name(parts.next()?)?;
    let group = parts.next()?.to_string();
    if group.is_empty() {
        return None;
    }
    let source = parts
        .next()
        .filter(|s| !s.is_empty() && *s != "*" && *s != "0.0.0.0")
        .map(str::to_string);
    Some((vlan, group, source))
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    if !p.igmp_snooping_supported() {
        return Ok(json!({
            "capability": Capability::no(UNSUPPORTED),
            "vlans": [], "groups": [],
        }));
    }

    // Every VLAN appears, snooping row or not, so the page lists them all.
    let mut vlans = Vec::new();
    for vlan_id in key_id_sorted_vlans(&plat.scan(CONFIG_DB, "VLAN|*")?) {
        let cfg = row(plat, CONFIG_DB, &format!("CFG_L2MC_TABLE|Vlan{vlan_id}"));
        vlans.push(VlanDoc {
            vlan_id,
            enabled: parse_bool(field(&cfg, "enabled")).unwrap_or(false),
            querier: parse_bool(field(&cfg, "querier")).unwrap_or(false),
            fast_leave: parse_bool(field(&cfg, "fast-leave")).unwrap_or(false),
            version: parse_num(field(&cfg, "version")).and_then(|n| u32::try_from(n).ok()),
            query_interval: parse_num(field(&cfg, "query-interval")),
            last_member_query_interval: parse_num(field(&cfg, "last-member-query-interval")),
            query_max_response_time: parse_num(field(&cfg, "query-max-response-time")),
        });
    }

    let mut groups = Vec::new();
    for key in keys(plat, APPL_DB, "APP_L2MC_MEMBER_TABLE:*") {
        let Some((vlan_id, group_address, source_address)) = parse_group_key(&key) else {
            continue;
        };
        let r = row(plat, APPL_DB, &key);
        let ports = field(&r, "ports@")
            .or_else(|| field(&r, "ports"))
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        groups.push(GroupDoc {
            vlan_id,
            group_address,
            source_address,
            ports,
            origin: if field(&r, "type") == Some("static") { "static" } else { "dynamic" },
        });
    }
    groups.sort_by(|a, b| {
        a.vlan_id.cmp(&b.vlan_id).then_with(|| a.group_address.cmp(&b.group_address))
    });

    Ok(json!({ "capability": Capability::yes(), "vlans": vlans, "groups": groups }))
}

// ── PUT /api/switching/igmp-snooping/vlans/{vlan_id} ────────────────────────

#[derive(Debug, Deserialize)]
pub struct VlanInput {
    pub enabled: bool,
    pub querier: bool,
    pub fast_leave: bool,
    pub version: Option<u32>,
    pub query_interval: Option<u64>,
    pub last_member_query_interval: Option<u64>,
    pub query_max_response_time: Option<u64>,
}

pub fn put_vlan(plat: &mut dyn Platform, vlan_id: u32, input: &VlanInput) -> WriteResult {
    let _lock = store::feature_lock("igmp");
    let p = probe::current(plat);
    if !p.igmp_snooping_supported() {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    if let Some(v) = input.version {
        if !(1..=3).contains(&v) {
            return Err(WriteError::BadRequest(format!("invalid version {v} (must be 1-3)")));
        }
    }
    for (name, v, lo, hi) in [
        ("query_interval", input.query_interval, 1, 18_000),
        ("last_member_query_interval", input.last_member_query_interval, 100, 25_500),
        ("query_max_response_time", input.query_max_response_time, 1, 25),
    ] {
        if let Some(v) = v {
            if !(lo..=hi).contains(&v) {
                return Err(WriteError::BadRequest(format!(
                    "invalid {name} {v} (must be {lo}-{hi})"
                )));
            }
        }
    }
    if !plat.exists(CONFIG_DB, &format!("VLAN|Vlan{vlan_id}")).map_err(WriteError::Redis)? {
        return Err(WriteError::NotFound(format!("no such VLAN Vlan{vlan_id}")));
    }

    let key = format!("CFG_L2MC_TABLE|Vlan{vlan_id}");
    let as_bool = |v: bool| if v { "true" } else { "false" };
    plat.hset(
        CONFIG_DB,
        &key,
        &[
            ("enabled", as_bool(input.enabled)),
            ("querier", as_bool(input.querier)),
            ("fast-leave", as_bool(input.fast_leave)),
        ],
    )
    .map_err(WriteError::Redis)?;
    // The body is the full desired document — absent tunables clear their
    // override back to the daemon default.
    for (fname, v) in [
        ("version", input.version.map(u64::from)),
        ("query-interval", input.query_interval),
        ("last-member-query-interval", input.last_member_query_interval),
        ("query-max-response-time", input.query_max_response_time),
    ] {
        match v {
            Some(v) => plat
                .hset(CONFIG_DB, &key, &[(fname, &v.to_string())])
                .map_err(WriteError::Redis)?,
            None => plat.hdel(CONFIG_DB, &key, &[fname]).map_err(WriteError::Redis)?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::*;

    fn enterprise() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file(
            "/etc/sonic/sonic_version.yml",
            "build_version: '4.1.1'\nrelease: 'Enterprise SONiC'\n",
        );
        m.seed(CONFIG_DB, "VLAN|Vlan10", &[("vlanid", "10")]);
        m.seed(CONFIG_DB, "VLAN|Vlan20", &[("vlanid", "20")]);
        m
    }

    #[test]
    fn community_is_unsupported_with_reason() {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202505.1'\n");
        m.seed(CONFIG_DB, "VLAN|Vlan10", &[("vlanid", "10")]);
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        assert_eq!(doc["capability"]["reason"], UNSUPPORTED);
        assert_eq!(doc["vlans"], json!([]));
        let err = put_vlan(
            &mut m,
            10,
            &VlanInput {
                enabled: true,
                querier: false,
                fast_leave: false,
                version: None,
                query_interval: None,
                last_member_query_interval: None,
                query_max_response_time: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
        // Nothing was written.
        assert!(!m.has_key(CONFIG_DB, "CFG_L2MC_TABLE|Vlan10"));
    }

    #[test]
    fn enterprise_lists_every_vlan_and_maps_groups() {
        let mut m = enterprise();
        m.seed(
            CONFIG_DB,
            "CFG_L2MC_TABLE|Vlan10",
            &[("enabled", "true"), ("querier", "true"), ("version", "2"), ("query-interval", "125")],
        );
        m.seed(
            APPL_DB,
            "APP_L2MC_MEMBER_TABLE:Vlan10:239.1.1.1",
            &[("ports@", "Ethernet0,Ethernet4"), ("type", "dynamic")],
        );
        m.seed(
            APPL_DB,
            "APP_L2MC_MEMBER_TABLE:Vlan10:239.1.1.2:10.0.0.5",
            &[("ports@", "Ethernet4"), ("type", "static")],
        );
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        let vlans = doc["vlans"].as_array().unwrap();
        assert_eq!(vlans.len(), 2);
        assert_eq!(vlans[0]["vlan_id"], 10);
        assert_eq!(vlans[0]["enabled"], true);
        assert_eq!(vlans[0]["version"], 2);
        // Vlan20 has no snooping row but still appears, disabled.
        assert_eq!(vlans[1]["vlan_id"], 20);
        assert_eq!(vlans[1]["enabled"], false);
        let groups = doc["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["group_address"], "239.1.1.1");
        assert_eq!(groups[0]["source_address"], serde_json::Value::Null);
        assert_eq!(groups[0]["ports"], json!(["Ethernet0", "Ethernet4"]));
        assert_eq!(groups[0]["origin"], "dynamic");
        assert_eq!(groups[1]["source_address"], "10.0.0.5");
        assert_eq!(groups[1]["origin"], "static");
    }

    #[test]
    fn enterprise_put_writes_and_clears_tunables() {
        let mut m = enterprise();
        put_vlan(
            &mut m,
            10,
            &VlanInput {
                enabled: true,
                querier: true,
                fast_leave: false,
                version: Some(3),
                query_interval: Some(60),
                last_member_query_interval: None,
                query_max_response_time: None,
            },
        )
        .unwrap();
        let row = m.row(CONFIG_DB, "CFG_L2MC_TABLE|Vlan10");
        assert_eq!(row.get("enabled").unwrap(), "true");
        assert_eq!(row.get("querier").unwrap(), "true");
        assert_eq!(row.get("fast-leave").unwrap(), "false");
        assert_eq!(row.get("version").unwrap(), "3");
        assert_eq!(row.get("query-interval").unwrap(), "60");
        assert!(row.get("last-member-query-interval").is_none());
        // Missing VLAN → 404; bad ranges → 400.
        let err = put_vlan(
            &mut m,
            30,
            &VlanInput {
                enabled: true,
                querier: false,
                fast_leave: false,
                version: None,
                query_interval: None,
                last_member_query_interval: None,
                query_max_response_time: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
        let err = put_vlan(
            &mut m,
            10,
            &VlanInput {
                enabled: true,
                querier: false,
                fast_leave: false,
                version: Some(4),
                query_interval: None,
                last_member_query_interval: None,
                query_max_response_time: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
    }

    #[test]
    fn group_keys_parse_defensively() {
        assert_eq!(
            parse_group_key("APP_L2MC_MEMBER_TABLE:Vlan10:239.0.0.1"),
            Some((10, "239.0.0.1".to_string(), None))
        );
        assert_eq!(
            parse_group_key("APP_L2MC_MEMBER_TABLE:Vlan10:239.0.0.1:10.1.1.1"),
            Some((10, "239.0.0.1".to_string(), Some("10.1.1.1".to_string())))
        );
        // "*" and 0.0.0.0 sources mean "any" → null.
        assert_eq!(
            parse_group_key("APP_L2MC_MEMBER_TABLE:Vlan10:239.0.0.1:*"),
            Some((10, "239.0.0.1".to_string(), None))
        );
        assert_eq!(parse_group_key("APP_L2MC_MEMBER_TABLE:notavlan:239.0.0.1"), None);
        assert_eq!(parse_group_key("OTHER:Vlan10:239.0.0.1"), None);
    }
}
