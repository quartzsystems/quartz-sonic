//! MCLAG for the console's High Availability section.
//!
//! Backed by CONFIG_DB `MCLAG_DOMAIN` (SONiC supports one domain per switch)
//! and `MCLAG_INTERFACE` (the member port channels), consumed by iccpd. The
//! console configures MCLAG per switch *pair* and writes each switch's half
//! separately — the agent only ever manages its own switch's domain and needs
//! no notion of the pair. Live state comes from `mclagdctl` (session/role
//! from `dump state`, remote member state from `dump portlist peer`) plus
//! APPL_DB LAG oper status for the local side; every state read degrades to
//! null/unknown, never an error.

use std::net::IpAddr;

use serde::Deserialize;
use serde_json::json;

use super::fdb::normalize_mac;
use super::probe::{self, Capability};
use super::store::{self, field, key_suffix, keys, row, two_parts, Platform};
use super::switching::{parse_num, WriteError, WriteResult};
use super::{APPL_DB, CONFIG_DB};

const UNSUPPORTED: &str = "MCLAG requires an image with iccpd \
     (Enterprise SONiC or a community build with the mclag feature)";

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

// ── GET /api/ha/mclag ───────────────────────────────────────────────────────

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    let capability =
        if p.mclag_supported() { Capability::yes() } else { Capability::no(UNSUPPORTED) };

    let domain_id = keys(plat, CONFIG_DB, "MCLAG_DOMAIN|*")
        .iter()
        .filter_map(|k| key_suffix(k, "MCLAG_DOMAIN|"))
        .filter_map(|s| s.parse::<u32>().ok())
        .min();
    let Some(domain_id) = domain_id else {
        return Ok(json!({ "capability": capability, "domain": null, "state": null }));
    };

    let cfg = row(plat, CONFIG_DB, &format!("MCLAG_DOMAIN|{domain_id}"));
    let mut members: Vec<String> = keys(plat, CONFIG_DB, "MCLAG_INTERFACE|*")
        .iter()
        .filter_map(|k| two_parts(k, "MCLAG_INTERFACE|"))
        .filter(|(id, _)| id.parse::<u32>().ok() == Some(domain_id))
        .map(|(_, name)| name.to_string())
        .collect();
    members.sort();
    let peer_link = field(&cfg, "peer_link").map(str::to_string);

    let state = live_state(plat, domain_id, peer_link.as_deref(), &members);
    let domain = json!({
        "domain_id": domain_id,
        "source_ip": field(&cfg, "source_ip").unwrap_or(""),
        "peer_ip": field(&cfg, "peer_ip").unwrap_or(""),
        "peer_link": peer_link,
        "keepalive_interval_s": parse_num(field(&cfg, "keepalive_interval")),
        "session_timeout_s": parse_num(field(&cfg, "session_timeout")),
        "system_mac": field(&cfg, "system_mac"),
        "members": members,
    });
    Ok(json!({ "capability": capability, "domain": domain, "state": state }))
}

/// Live iccpd state; None when mclagdctl isn't there / fails (iccpd down).
fn live_state(
    plat: &mut dyn Platform,
    domain_id: u32,
    peer_link: Option<&str>,
    members: &[String],
) -> Option<serde_json::Value> {
    let id = domain_id.to_string();
    let dump = plat.run("mclagdctl", &["-i", &id, "dump", "state"]).ok().filter(|o| o.ok)?;
    let (session_status, role) = parse_dump_state(&dump.stdout);
    let remote = plat
        .run("mclagdctl", &["-i", &id, "dump", "portlist", "peer"])
        .ok()
        .filter(|o| o.ok)
        .map(|o| parse_portlist_states(&o.stdout))
        .unwrap_or_default();
    let member_states: Vec<serde_json::Value> = members
        .iter()
        .map(|m| {
            json!({
                "name": m,
                "local_status": lag_oper_status(plat, m).unwrap_or("unknown"),
                "remote_status": match remote.get(m.as_str()).map(String::as_str) {
                    Some("up") => "up",
                    Some("down") => "down",
                    _ => "unknown",
                },
            })
        })
        .collect();
    Some(json!({
        "session_status": session_status,
        "role": role,
        "peer_link_status": peer_link.and_then(|pl| lag_oper_status(plat, pl)),
        "members": member_states,
    }))
}

/// APPL_DB LAG_TABLE oper status; None when the row doesn't say.
fn lag_oper_status(plat: &mut dyn Platform, name: &str) -> Option<&'static str> {
    match field(&row(plat, APPL_DB, &format!("LAG_TABLE:{name}")), "oper_status")
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("up") => Some("up"),
        Some("down") => Some("down"),
        _ => None,
    }
}

/// (session_status, role) from `mclagdctl dump state` output. Pure, tolerant:
/// unrecognized values stay None (serialized as null). The "Keepalive time"
/// config line must not shadow the "keepalive is: OK" status line.
pub fn parse_dump_state(text: &str) -> (Option<&'static str>, Option<&'static str>) {
    let mut session = None;
    let mut role = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        if k.contains("keepalive") && !k.contains("time") {
            session = Some(if v.eq_ignore_ascii_case("ok") { "up" } else { "down" });
        } else if k == "role" {
            role = match v.to_ascii_lowercase().as_str() {
                "active" => Some("active"),
                "standby" => Some("standby"),
                _ => None,
            };
        }
    }
    (session, role)
}

/// PortName → lowercased State from `mclagdctl dump portlist` output. Pure.
pub fn parse_portlist_states(text: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        match k.trim().to_ascii_lowercase().as_str() {
            "portname" => current = Some(v.trim().to_string()),
            "state" | "operstate" => {
                if let Some(name) = &current {
                    out.insert(name.clone(), v.trim().to_ascii_lowercase());
                }
            }
            _ => {}
        }
    }
    out
}

// ── PUT /api/ha/mclag ───────────────────────────────────────────────────────

/// The whole desired domain — an upsert replaces the switch's MCLAG_DOMAIN
/// row and diffs `members` against MCLAG_INTERFACE.
#[derive(Debug, Deserialize)]
pub struct DomainInput {
    pub domain_id: u32,
    pub source_ip: String,
    pub peer_ip: String,
    pub peer_link: Option<String>,
    pub keepalive_interval_s: Option<u32>,
    pub session_timeout_s: Option<u32>,
    pub system_mac: Option<String>,
    pub members: Vec<String>,
}

pub fn put(plat: &mut dyn Platform, input: &DomainInput) -> WriteResult {
    let _lock = store::feature_lock("mclag");
    if !(1..=4095).contains(&input.domain_id) {
        return Err(bad(format!("invalid domain_id {} (must be 1-4095)", input.domain_id)));
    }
    let source: IpAddr = input
        .source_ip
        .parse()
        .map_err(|_| bad(format!("invalid source_ip {:?}", input.source_ip)))?;
    let peer: IpAddr =
        input.peer_ip.parse().map_err(|_| bad(format!("invalid peer_ip {:?}", input.peer_ip)))?;
    if source == peer {
        return Err(bad("source_ip and peer_ip must differ"));
    }
    if let Some(k) = input.keepalive_interval_s {
        if !(1..=60).contains(&k) {
            return Err(bad(format!("invalid keepalive_interval_s {k} (must be 1-60)")));
        }
    }
    if let Some(t) = input.session_timeout_s {
        if !(3..=3600).contains(&t) {
            return Err(bad(format!("invalid session_timeout_s {t} (must be 3-3600)")));
        }
    }
    let system_mac = match &input.system_mac {
        None => None,
        Some(m) => {
            let Some(canonical) = normalize_mac(m) else {
                return Err(bad(format!(
                    "invalid system_mac {m:?} (expected e.g. 00:11:22:33:44:55)"
                )));
            };
            let first = u8::from_str_radix(&canonical[..2], 16).expect("normalized hex");
            if first & 1 == 1 || canonical == "00:00:00:00:00:00" {
                return Err(bad(format!(
                    "system_mac {canonical} must be a unicast, non-zero MAC"
                )));
            }
            Some(canonical)
        }
    };
    let mut seen = Vec::new();
    for m in &input.members {
        if seen.contains(&m) {
            return Err(bad(format!("duplicate member {m}")));
        }
        seen.push(m);
        if Some(m.as_str()) == input.peer_link.as_deref() {
            return Err(bad(format!("member {m} cannot also be the peer link")));
        }
    }

    if !probe::current(plat).mclag_supported() {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    if let Some(pl) = &input.peer_link {
        if !plat.exists(CONFIG_DB, &format!("PORTCHANNEL|{pl}"))? {
            return Err(bad(format!("peer_link {pl} is not an existing port channel")));
        }
    }
    for m in &input.members {
        if !plat.exists(CONFIG_DB, &format!("PORTCHANNEL|{m}"))? {
            return Err(bad(format!("member {m} is not an existing port channel")));
        }
    }

    // One domain per switch: an upsert under a new id replaces the old
    // domain; member rows not in the desired set go too.
    for key in keys(plat, CONFIG_DB, "MCLAG_DOMAIN|*") {
        if key != format!("MCLAG_DOMAIN|{}", input.domain_id) {
            plat.del(CONFIG_DB, &key)?;
        }
    }
    for key in keys(plat, CONFIG_DB, "MCLAG_INTERFACE|*") {
        let stale = match two_parts(&key, "MCLAG_INTERFACE|") {
            Some((id, name)) => {
                id.parse::<u32>().ok() != Some(input.domain_id)
                    || !input.members.iter().any(|m| m == name)
            }
            None => true,
        };
        if stale {
            plat.del(CONFIG_DB, &key)?;
        }
    }
    // Replace the whole row so cleared optionals never linger.
    let key = format!("MCLAG_DOMAIN|{}", input.domain_id);
    plat.del(CONFIG_DB, &key)?;
    let mut fields: Vec<(&str, String)> = vec![
        ("source_ip", input.source_ip.clone()),
        ("peer_ip", input.peer_ip.clone()),
    ];
    if let Some(pl) = &input.peer_link {
        fields.push(("peer_link", pl.clone()));
    }
    if let Some(k) = input.keepalive_interval_s {
        fields.push(("keepalive_interval", k.to_string()));
    }
    if let Some(t) = input.session_timeout_s {
        fields.push(("session_timeout", t.to_string()));
    }
    if let Some(mac) = &system_mac {
        fields.push(("system_mac", mac.clone()));
    }
    let refs: Vec<(&str, &str)> = fields.iter().map(|(f, v)| (*f, v.as_str())).collect();
    plat.hset(CONFIG_DB, &key, &refs)?;
    for m in &input.members {
        plat.hset(
            CONFIG_DB,
            &format!("MCLAG_INTERFACE|{}|{m}", input.domain_id),
            &[("if_type", "PortChannel")],
        )?;
    }
    Ok(())
}

// ── DELETE /api/ha/mclag ────────────────────────────────────────────────────

pub fn delete(plat: &mut dyn Platform) -> WriteResult {
    let _lock = store::feature_lock("mclag");
    let domain_keys = keys(plat, CONFIG_DB, "MCLAG_DOMAIN|*");
    if domain_keys.is_empty() {
        return Err(WriteError::NotFound("MCLAG is not configured on this switch".into()));
    }
    for key in keys(plat, CONFIG_DB, "MCLAG_INTERFACE|*") {
        plat.del(CONFIG_DB, &key)?;
    }
    for key in domain_keys {
        plat.del(CONFIG_DB, &key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::super::store::CmdOutput;
    use super::*;

    fn platform() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        m.seed(CONFIG_DB, "FEATURE|mclag", &[("state", "enabled")]);
        m.seed(CONFIG_DB, "PORTCHANNEL|PortChannel0001", &[("admin_status", "up")]);
        m.seed(CONFIG_DB, "PORTCHANNEL|PortChannel0002", &[("admin_status", "up")]);
        m
    }

    fn input() -> DomainInput {
        DomainInput {
            domain_id: 1,
            source_ip: "10.0.0.1".into(),
            peer_ip: "10.0.0.2".into(),
            peer_link: Some("PortChannel0001".into()),
            keepalive_interval_s: Some(1),
            session_timeout_s: Some(15),
            system_mac: Some("00:11:22:33:44:55".into()),
            members: vec!["PortChannel0002".into()],
        }
    }

    #[test]
    fn get_unconfigured() {
        let mut m = platform();
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["domain"], serde_json::Value::Null);
        assert_eq!(doc["state"], serde_json::Value::Null);
    }

    #[test]
    fn unsupported_without_iccpd() {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/sonic/sonic_version.yml", "build_version: '202311.1'\n");
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        let err = put(&mut m, &input()).unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
    }

    #[test]
    fn put_writes_domain_and_members() {
        let mut m = platform();
        put(&mut m, &input()).unwrap();
        let row = m.row(CONFIG_DB, "MCLAG_DOMAIN|1");
        assert_eq!(row.get("source_ip").unwrap(), "10.0.0.1");
        assert_eq!(row.get("peer_ip").unwrap(), "10.0.0.2");
        assert_eq!(row.get("peer_link").unwrap(), "PortChannel0001");
        assert_eq!(row.get("keepalive_interval").unwrap(), "1");
        assert_eq!(row.get("session_timeout").unwrap(), "15");
        assert_eq!(row.get("system_mac").unwrap(), "00:11:22:33:44:55");
        assert!(m.has_key(CONFIG_DB, "MCLAG_INTERFACE|1|PortChannel0002"));
        // Upsert without the optionals clears them from the row.
        let bare = DomainInput {
            peer_link: None,
            keepalive_interval_s: None,
            session_timeout_s: None,
            system_mac: None,
            members: vec![],
            ..input()
        };
        put(&mut m, &bare).unwrap();
        let row = m.row(CONFIG_DB, "MCLAG_DOMAIN|1");
        assert!(!row.contains_key("peer_link"));
        assert!(!row.contains_key("system_mac"));
        assert!(!m.has_key(CONFIG_DB, "MCLAG_INTERFACE|1|PortChannel0002"));
    }

    #[test]
    fn put_replaces_previous_domain() {
        let mut m = platform();
        m.seed(
            CONFIG_DB,
            "MCLAG_DOMAIN|7",
            &[("source_ip", "10.0.0.9"), ("peer_ip", "10.0.0.10")],
        );
        m.seed(CONFIG_DB, "MCLAG_INTERFACE|7|PortChannel0001", &[("if_type", "PortChannel")]);
        put(&mut m, &input()).unwrap();
        assert!(!m.has_key(CONFIG_DB, "MCLAG_DOMAIN|7"));
        assert!(!m.has_key(CONFIG_DB, "MCLAG_INTERFACE|7|PortChannel0001"));
        assert!(m.has_key(CONFIG_DB, "MCLAG_DOMAIN|1"));
    }

    #[test]
    fn put_validation() {
        let mut m = platform();
        let mut bad_id = input();
        bad_id.domain_id = 0;
        let mut same_ips = input();
        same_ips.peer_ip = same_ips.source_ip.clone();
        let mut bad_ip = input();
        bad_ip.source_ip = "not-an-ip".into();
        let mut bad_keepalive = input();
        bad_keepalive.keepalive_interval_s = Some(0);
        let mut bad_mac = input();
        bad_mac.system_mac = Some("01:00:5e:00:00:01".into()); // multicast
        let mut unknown_peer_link = input();
        unknown_peer_link.peer_link = Some("PortChannel0099".into());
        let mut unknown_member = input();
        unknown_member.members = vec!["PortChannel0099".into()];
        let mut member_is_peer_link = input();
        member_is_peer_link.members = vec!["PortChannel0001".into()];
        let mut dup_member = input();
        dup_member.members = vec!["PortChannel0002".into(), "PortChannel0002".into()];
        for i in [
            bad_id,
            same_ips,
            bad_ip,
            bad_keepalive,
            bad_mac,
            unknown_peer_link,
            unknown_member,
            member_is_peer_link,
            dup_member,
        ] {
            let err = put(&mut m, &i).unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{err:?}");
        }
        assert!(!m.has_key(CONFIG_DB, "MCLAG_DOMAIN|1"));
    }

    #[test]
    fn get_reports_domain_and_state() {
        let mut m = platform();
        put(&mut m, &input()).unwrap();
        m.on_cmd(
            &["mclagdctl", "-i", "1", "dump", "state"],
            CmdOutput {
                ok: true,
                stdout: "The MCLAG's keepalive is: OK\nDomain id: 1\nKeepalive time: 1\n\
                         sesssion Timeout : 15\nRole: Active\n"
                    .into(),
                stderr: String::new(),
            },
        );
        m.on_cmd(
            &["mclagdctl", "-i", "1", "dump", "portlist", "peer"],
            CmdOutput {
                ok: true,
                stdout: "Ifindex: 105\nType: PortChannel\nPortName: PortChannel0002\nState: Up\n"
                    .into(),
                stderr: String::new(),
            },
        );
        m.seed(APPL_DB, "LAG_TABLE:PortChannel0001", &[("oper_status", "up")]);
        m.seed(APPL_DB, "LAG_TABLE:PortChannel0002", &[("oper_status", "down")]);
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["domain"]["domain_id"], 1);
        assert_eq!(doc["domain"]["source_ip"], "10.0.0.1");
        assert_eq!(doc["domain"]["members"], json!(["PortChannel0002"]));
        assert_eq!(doc["state"]["session_status"], "up");
        assert_eq!(doc["state"]["role"], "active");
        assert_eq!(doc["state"]["peer_link_status"], "up");
        assert_eq!(doc["state"]["members"][0]["name"], "PortChannel0002");
        assert_eq!(doc["state"]["members"][0]["local_status"], "down");
        assert_eq!(doc["state"]["members"][0]["remote_status"], "up");
    }

    #[test]
    fn delete_removes_everything() {
        let mut m = platform();
        put(&mut m, &input()).unwrap();
        delete(&mut m).unwrap();
        assert!(!m.has_key(CONFIG_DB, "MCLAG_DOMAIN|1"));
        assert!(!m.has_key(CONFIG_DB, "MCLAG_INTERFACE|1|PortChannel0002"));
        assert!(matches!(delete(&mut m).unwrap_err(), WriteError::NotFound(_)));
    }

    #[test]
    fn dump_state_parsing() {
        assert_eq!(
            parse_dump_state("The MCLAG's keepalive is: OK\nKeepalive time: 1\nRole: Standby\n"),
            (Some("up"), Some("standby"))
        );
        assert_eq!(
            parse_dump_state("The MCLAG's keepalive is: ERROR\nRole: None\n"),
            (Some("down"), None)
        );
        assert_eq!(parse_dump_state(""), (None, None));
    }

    #[test]
    fn portlist_parsing() {
        let states = parse_portlist_states(
            "Ifindex: 105\nType: PortChannel\nPortName: PortChannel0002\nState: Up\n\
             ------\nIfindex: 106\nPortName: PortChannel0003\nState: Down\n",
        );
        assert_eq!(states.get("PortChannel0002").unwrap(), "up");
        assert_eq!(states.get("PortChannel0003").unwrap(), "down");
    }
}
