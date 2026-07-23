//! Port mirroring (SPAN/ERSPAN) for the console's Configure → Switching →
//! Port Mirroring page.
//!
//! Backed by the CONFIG_DB `MIRROR_SESSION` table, which every image's
//! orchagent consumes. ERSPAN sessions (src_ip/dst_ip GRE tunnels) are the
//! original schema; SPAN sessions (`type=SPAN`, a local `dst_port`) need a
//! 202012+ image — writes of a SPAN session on older images are refused with
//! a clear error. sonic-utilities stores `direction` and `type` uppercase
//! and `src_port` as a comma-joined string; reads here tolerate any case.
//! Operational status comes from STATE_DB `MIRROR_SESSION_TABLE|<name>`.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, field, key_suffix, keys, row, Platform};
use super::switching::{parse_num, WriteError, WriteResult};
use super::{CONFIG_DB, STATE_DB};

const SPAN_UNSUPPORTED: &str =
    "SPAN mirror sessions require SONiC 202012 or newer; this image only supports ERSPAN.";

#[derive(Debug, Serialize)]
struct ErspanDoc {
    src_ip: Option<String>,
    dst_ip: Option<String>,
    gre_type: Option<String>,
    dscp: Option<u64>,
    ttl: Option<u64>,
    queue: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SessionDoc {
    name: String,
    #[serde(rename = "type")]
    session_type: &'static str,
    source_ports: Vec<String>,
    direction: &'static str,
    dst_port: Option<String>,
    erspan: Option<ErspanDoc>,
    status: Option<&'static str>,
}

/// Split a MIRROR_SESSION `src_port` comma list. Pure.
pub fn split_ports(v: Option<&str>) -> Vec<String> {
    v.map(|s| {
        s.split(',').map(str::trim).filter(|p| !p.is_empty()).map(str::to_string).collect()
    })
    .unwrap_or_default()
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let p = probe::current(plat);
    let capability = if p.span_mirror_supported() {
        Capability::yes()
    } else {
        // Mirroring itself works everywhere — the reason just flags the
        // SPAN limitation for the UI.
        Capability::yes_with_reason(SPAN_UNSUPPORTED)
    };

    let mut sessions = Vec::new();
    for key in keys(plat, CONFIG_DB, "MIRROR_SESSION|*") {
        let Some(name) = key_suffix(&key, "MIRROR_SESSION|") else { continue };
        let cfg = row(plat, CONFIG_DB, &key);
        // `type` is authoritative when present; legacy ERSPAN rows have no
        // type field at all.
        let is_span = field(&cfg, "type").is_some_and(|t| t.eq_ignore_ascii_case("span"));
        let direction = match field(&cfg, "direction").map(str::to_ascii_lowercase).as_deref() {
            Some("rx") => "rx",
            Some("tx") => "tx",
            _ => "both", // SONiC's default when unset
        };
        let state = row(plat, STATE_DB, &format!("MIRROR_SESSION_TABLE|{name}"));
        let status = match field(&state, "status").map(str::to_ascii_lowercase).as_deref() {
            Some("active") => Some("active"),
            Some("inactive") => Some("inactive"),
            _ => None,
        };
        sessions.push(SessionDoc {
            name: name.to_string(),
            session_type: if is_span { "span" } else { "erspan" },
            source_ports: split_ports(field(&cfg, "src_port")),
            direction,
            dst_port: if is_span { field(&cfg, "dst_port").map(str::to_string) } else { None },
            erspan: (!is_span).then(|| ErspanDoc {
                src_ip: field(&cfg, "src_ip").map(str::to_string),
                dst_ip: field(&cfg, "dst_ip").map(str::to_string),
                gre_type: field(&cfg, "gre_type").map(str::to_string),
                dscp: parse_num(field(&cfg, "dscp")),
                ttl: parse_num(field(&cfg, "ttl")),
                queue: parse_num(field(&cfg, "queue")),
            }),
            status,
        });
    }
    sessions.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(json!({ "capability": capability, "sessions": sessions }))
}

// ── PUT /api/switching/mirror-sessions/{name} ───────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    Span,
    Erspan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Rx,
    Tx,
    Both,
}

impl Direction {
    fn as_config(self) -> &'static str {
        match self {
            Direction::Rx => "RX",
            Direction::Tx => "TX",
            Direction::Both => "BOTH",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ErspanInput {
    pub src_ip: String,
    pub dst_ip: String,
    pub gre_type: Option<String>,
    pub dscp: Option<u8>,
    pub ttl: Option<u16>,
    pub queue: Option<u32>,
}

/// The whole desired session, minus name/status — an upsert replaces the row.
#[derive(Debug, Deserialize)]
pub struct SessionInput {
    #[serde(rename = "type")]
    pub session_type: SessionType,
    pub source_ports: Vec<String>,
    pub direction: Direction,
    pub dst_port: Option<String>,
    pub erspan: Option<ErspanInput>,
}

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

fn check_name(name: &str) -> WriteResult {
    if name.is_empty() || name.contains('|') || name.contains(char::is_whitespace) {
        return Err(bad(format!("invalid mirror session name {name:?}")));
    }
    Ok(())
}

fn check_ip(label: &str, v: &str) -> WriteResult {
    v.parse::<IpAddr>()
        .map(|_| ())
        .map_err(|_| bad(format!("invalid {label} {v:?} (expected an IP address)")))
}

/// gre_type is a 16-bit GRE protocol number, hex ("0x88be") or decimal.
fn check_gre_type(v: &str) -> WriteResult {
    let parsed = match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        Some(hex) => u16::from_str_radix(hex, 16).ok(),
        None => v.parse::<u16>().ok(),
    };
    match parsed {
        Some(_) => Ok(()),
        None => Err(bad(format!("invalid gre_type {v:?} (expected e.g. \"0x88be\")"))),
    }
}

pub fn put_session(plat: &mut dyn Platform, name: &str, input: &SessionInput) -> WriteResult {
    let _lock = store::feature_lock("mirror");
    check_name(name)?;
    if input.source_ports.is_empty() {
        return Err(bad("a mirror session needs at least one source port"));
    }
    let mut seen = Vec::new();
    for port in &input.source_ports {
        if seen.contains(&port) {
            return Err(bad(format!("duplicate source port {port}")));
        }
        seen.push(port);
    }

    // Everything image-independent is validated before probing/writing.
    match input.session_type {
        SessionType::Span => {
            if input.erspan.is_some() {
                return Err(bad("a span session does not take erspan parameters"));
            }
            if input.dst_port.as_deref().is_none_or(str::is_empty) {
                return Err(bad("a span session requires dst_port"));
            }
        }
        SessionType::Erspan => {
            if input.dst_port.is_some() {
                return Err(bad("an erspan session does not take dst_port"));
            }
            let Some(e) = &input.erspan else {
                return Err(bad("an erspan session requires src_ip and dst_ip"));
            };
            check_ip("src_ip", &e.src_ip)?;
            check_ip("dst_ip", &e.dst_ip)?;
            if let Some(g) = &e.gre_type {
                check_gre_type(g)?;
            }
            if let Some(d) = e.dscp {
                if d > 63 {
                    return Err(bad(format!("invalid dscp {d} (must be 0-63)")));
                }
            }
            if let Some(t) = e.ttl {
                if !(1..=255).contains(&t) {
                    return Err(bad(format!("invalid ttl {t} (must be 1-255)")));
                }
            }
        }
    }

    let p = probe::current(plat);
    let span_ok = p.span_mirror_supported();
    if input.session_type == SessionType::Span && !span_ok {
        return Err(WriteError::Conflict(SPAN_UNSUPPORTED.to_string()));
    }

    for port in &input.source_ports {
        let exists = plat.exists(CONFIG_DB, &format!("PORT|{port}"))?
            || plat.exists(CONFIG_DB, &format!("PORTCHANNEL|{port}"))?;
        if !exists {
            return Err(bad(format!("no such interface {port}")));
        }
    }
    if let Some(dst) = &input.dst_port {
        // The analyzer port must be a physical port, and copying a port's
        // traffic to itself is never what anyone means.
        if !plat.exists(CONFIG_DB, &format!("PORT|{dst}"))? {
            return Err(bad(format!("dst_port {dst} is not a physical port")));
        }
        if input.source_ports.iter().any(|s| s == dst) {
            return Err(bad(format!("dst_port {dst} cannot also be a source port")));
        }
    }

    // Upsert = replace the whole row, so stale fields from a previous type
    // never linger.
    let key = format!("MIRROR_SESSION|{name}");
    plat.del(CONFIG_DB, &key)?;
    let src = input.source_ports.join(",");
    let mut fields: Vec<(&str, String)> = vec![
        ("src_port", src),
        ("direction", input.direction.as_config().to_string()),
    ];
    match input.session_type {
        SessionType::Span => {
            fields.push(("type", "SPAN".to_string()));
            fields.push(("dst_port", input.dst_port.clone().expect("validated above")));
        }
        SessionType::Erspan => {
            let e = input.erspan.as_ref().expect("validated above");
            // Pre-202012 mirrororch doesn't know the type field — legacy
            // ERSPAN rows are written without it, exactly as the old CLI did.
            if span_ok {
                fields.push(("type", "ERSPAN".to_string()));
            }
            fields.push(("src_ip", e.src_ip.clone()));
            fields.push(("dst_ip", e.dst_ip.clone()));
            if let Some(g) = &e.gre_type {
                fields.push(("gre_type", g.clone()));
            }
            if let Some(d) = e.dscp {
                fields.push(("dscp", d.to_string()));
            }
            if let Some(t) = e.ttl {
                fields.push(("ttl", t.to_string()));
            }
            if let Some(q) = e.queue {
                fields.push(("queue", q.to_string()));
            }
        }
    }
    let refs: Vec<(&str, &str)> = fields.iter().map(|(f, v)| (*f, v.as_str())).collect();
    plat.hset(CONFIG_DB, &key, &refs)?;
    Ok(())
}

// ── DELETE /api/switching/mirror-sessions/{name} ────────────────────────────

pub fn delete_session(plat: &mut dyn Platform, name: &str) -> WriteResult {
    let _lock = store::feature_lock("mirror");
    let key = format!("MIRROR_SESSION|{name}");
    if !plat.exists(CONFIG_DB, &key)? {
        return Err(WriteError::NotFound(format!("no such mirror session {name}")));
    }
    // Flow-based mirroring binds sessions to ACL rules; deleting a session
    // out from under one would strand the rule.
    for rule_key in keys(plat, CONFIG_DB, "ACL_RULE|*") {
        let rule = row(plat, CONFIG_DB, &rule_key);
        let referenced = ["MIRROR_ACTION", "MIRROR_INGRESS_ACTION", "MIRROR_EGRESS_ACTION"]
            .iter()
            .any(|f| field(&rule, f) == Some(name));
        if referenced {
            let rule_name = rule_key.strip_prefix("ACL_RULE|").unwrap_or(&rule_key);
            return Err(WriteError::Conflict(format!(
                "mirror session {name} is in use by ACL rule {rule_name}; remove the rule first"
            )));
        }
    }
    plat.del(CONFIG_DB, &key)?;
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
        m.seed(CONFIG_DB, "PORT|Ethernet47", &[("alias", "Eth1/48")]);
        m.seed(CONFIG_DB, "PORTCHANNEL|PortChannel0001", &[("admin_status", "up")]);
        m
    }

    fn span_input() -> SessionInput {
        SessionInput {
            session_type: SessionType::Span,
            source_ports: vec!["Ethernet0".into(), "PortChannel0001".into()],
            direction: Direction::Both,
            dst_port: Some("Ethernet47".into()),
            erspan: None,
        }
    }

    fn erspan_input() -> SessionInput {
        SessionInput {
            session_type: SessionType::Erspan,
            source_ports: vec!["Ethernet0".into()],
            direction: Direction::Rx,
            dst_port: None,
            erspan: Some(ErspanInput {
                src_ip: "10.0.0.1".into(),
                dst_ip: "10.9.0.50".into(),
                gre_type: Some("0x88be".into()),
                dscp: Some(8),
                ttl: Some(64),
                queue: None,
            }),
        }
    }

    #[test]
    fn get_maps_span_erspan_and_status() {
        let mut m = platform("202311.1");
        m.seed(
            CONFIG_DB,
            "MIRROR_SESSION|capture-uplink",
            &[
                ("type", "SPAN"),
                ("src_port", "Ethernet0,PortChannel0001"),
                ("direction", "BOTH"),
                ("dst_port", "Ethernet47"),
            ],
        );
        m.seed(
            CONFIG_DB,
            "MIRROR_SESSION|to-collector",
            &[
                ("src_ip", "10.0.0.1"),
                ("dst_ip", "10.9.0.50"),
                ("gre_type", "0x88be"),
                ("dscp", "8"),
                ("ttl", "64"),
                ("src_port", "Ethernet4"),
                ("direction", "RX"),
            ],
        );
        m.seed(STATE_DB, "MIRROR_SESSION_TABLE|to-collector", &[("status", "active")]);
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        let sessions = doc["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0]["name"], "capture-uplink");
        assert_eq!(sessions[0]["type"], "span");
        assert_eq!(sessions[0]["source_ports"], json!(["Ethernet0", "PortChannel0001"]));
        assert_eq!(sessions[0]["direction"], "both");
        assert_eq!(sessions[0]["dst_port"], "Ethernet47");
        assert_eq!(sessions[0]["erspan"], serde_json::Value::Null);
        assert_eq!(sessions[0]["status"], serde_json::Value::Null);
        assert_eq!(sessions[1]["type"], "erspan");
        assert_eq!(sessions[1]["dst_port"], serde_json::Value::Null);
        assert_eq!(sessions[1]["erspan"]["dst_ip"], "10.9.0.50");
        assert_eq!(sessions[1]["erspan"]["dscp"], 8);
        assert_eq!(sessions[1]["direction"], "rx");
        assert_eq!(sessions[1]["status"], "active");
    }

    #[test]
    fn old_image_reports_span_limitation() {
        let mut m = platform("201911.1");
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["capability"]["reason"], SPAN_UNSUPPORTED);
    }

    #[test]
    fn span_put_writes_full_row() {
        let mut m = platform("202311.1");
        put_session(&mut m, "cap", &span_input()).unwrap();
        let row = m.row(CONFIG_DB, "MIRROR_SESSION|cap");
        assert_eq!(row.get("type").unwrap(), "SPAN");
        assert_eq!(row.get("src_port").unwrap(), "Ethernet0,PortChannel0001");
        assert_eq!(row.get("direction").unwrap(), "BOTH");
        assert_eq!(row.get("dst_port").unwrap(), "Ethernet47");
    }

    #[test]
    fn span_rejected_on_old_images() {
        let mut m = platform("201911.5");
        let err = put_session(&mut m, "cap", &span_input()).unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
        assert!(!m.has_key(CONFIG_DB, "MIRROR_SESSION|cap"));
        // ERSPAN still works, written without the type field the old
        // mirrororch doesn't know.
        put_session(&mut m, "legacy", &erspan_input()).unwrap();
        let row = m.row(CONFIG_DB, "MIRROR_SESSION|legacy");
        assert!(!row.contains_key("type"));
        assert_eq!(row.get("dst_ip").unwrap(), "10.9.0.50");
    }

    #[test]
    fn erspan_put_replaces_row_and_stamps_type() {
        let mut m = platform("202311.1");
        // Pre-existing SPAN row: the upsert must not leave dst_port behind.
        m.seed(
            CONFIG_DB,
            "MIRROR_SESSION|s1",
            &[("type", "SPAN"), ("dst_port", "Ethernet47"), ("src_port", "Ethernet4")],
        );
        put_session(&mut m, "s1", &erspan_input()).unwrap();
        let row = m.row(CONFIG_DB, "MIRROR_SESSION|s1");
        assert_eq!(row.get("type").unwrap(), "ERSPAN");
        assert_eq!(row.get("src_ip").unwrap(), "10.0.0.1");
        assert_eq!(row.get("gre_type").unwrap(), "0x88be");
        assert_eq!(row.get("ttl").unwrap(), "64");
        assert!(!row.contains_key("dst_port"));
        assert!(!row.contains_key("queue"));
    }

    #[test]
    fn payload_validation_rejects_bad_sessions() {
        let mut m = platform("202311.1");
        let mut no_sources = span_input();
        no_sources.source_ports.clear();
        assert!(matches!(
            put_session(&mut m, "s", &no_sources).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        let mut no_dst = span_input();
        no_dst.dst_port = None;
        assert!(matches!(
            put_session(&mut m, "s", &no_dst).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        let mut dst_is_source = span_input();
        dst_is_source.dst_port = Some("Ethernet0".into());
        assert!(matches!(
            put_session(&mut m, "s", &dst_is_source).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        let mut lag_dst = span_input();
        lag_dst.dst_port = Some("PortChannel0001".into());
        lag_dst.source_ports = vec!["Ethernet0".into()];
        assert!(matches!(
            put_session(&mut m, "s", &lag_dst).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        let mut bad_ip = erspan_input();
        bad_ip.erspan.as_mut().unwrap().dst_ip = "not-an-ip".into();
        assert!(matches!(
            put_session(&mut m, "s", &bad_ip).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        let mut bad_gre = erspan_input();
        bad_gre.erspan.as_mut().unwrap().gre_type = Some("0xZZZZ".into());
        assert!(matches!(
            put_session(&mut m, "s", &bad_gre).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        let mut unknown_port = erspan_input();
        unknown_port.source_ports = vec!["Ethernet99".into()];
        assert!(matches!(
            put_session(&mut m, "s", &unknown_port).unwrap_err(),
            WriteError::BadRequest(_)
        ));
        assert!(matches!(
            put_session(&mut m, "bad|name", &erspan_input()).unwrap_err(),
            WriteError::BadRequest(_)
        ));
    }

    #[test]
    fn delete_refuses_while_acl_references_session() {
        let mut m = platform("202311.1");
        m.seed(CONFIG_DB, "MIRROR_SESSION|cap", &[("src_port", "Ethernet0")]);
        m.seed(
            CONFIG_DB,
            "ACL_RULE|EVERFLOW|RULE_10",
            &[("PRIORITY", "10"), ("MIRROR_ACTION", "cap")],
        );
        let err = delete_session(&mut m, "cap").unwrap_err();
        match err {
            WriteError::Conflict(msg) => assert!(msg.contains("EVERFLOW|RULE_10"), "{msg}"),
            other => panic!("expected Conflict, got {other:?}"),
        }
        assert!(m.has_key(CONFIG_DB, "MIRROR_SESSION|cap"));
        // Unreferenced sessions delete fine; missing ones are 404s.
        m.del(CONFIG_DB, "ACL_RULE|EVERFLOW|RULE_10").unwrap();
        delete_session(&mut m, "cap").unwrap();
        assert!(!m.has_key(CONFIG_DB, "MIRROR_SESSION|cap"));
        assert!(matches!(
            delete_session(&mut m, "cap").unwrap_err(),
            WriteError::NotFound(_)
        ));
    }
}
