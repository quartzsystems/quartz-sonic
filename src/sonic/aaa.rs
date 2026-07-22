//! AAA (login order, TACACS+, RADIUS) for the console's Configure →
//! Security → AAA page.
//!
//! Backed by the CONFIG_DB `AAA`, `TACPLUS`/`TACPLUS_SERVER`, and
//! `RADIUS`/`RADIUS_SERVER` tables — hostcfgd rewrites PAM/NSS from them on
//! every SONiC flavor, so the capability is always supported.
//!
//! Secrets are write-only: GET never returns a `passkey`, only `*_key_set`
//! booleans; on writes `key: null` means unchanged and `""` clears. The
//! authentication PUT refuses a login order without `"local"` — the UI
//! enforces it too, but the agent is the lockout backstop.

use serde::Deserialize;
use serde_json::json;

use super::probe::Capability;
use super::store::{self, field, key_suffix, row, Platform};
use super::switching::{parse_num, WriteError, WriteResult};
use super::CONFIG_DB;

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

/// The two server-based protocols, parameterizing table and field names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tacacs,
    Radius,
}

impl Proto {
    pub fn from_path(seg: &str) -> Option<Self> {
        match seg {
            "tacacs" => Some(Proto::Tacacs),
            "radius" => Some(Proto::Radius),
            _ => None,
        }
    }

    fn global_key(self) -> &'static str {
        match self {
            Proto::Tacacs => "TACPLUS|global",
            Proto::Radius => "RADIUS|global",
        }
    }

    fn server_table(self) -> &'static str {
        match self {
            Proto::Tacacs => "TACPLUS_SERVER",
            Proto::Radius => "RADIUS_SERVER",
        }
    }

    fn port_field(self) -> &'static str {
        match self {
            Proto::Tacacs => "tcp_port",
            Proto::Radius => "auth_port",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Proto::Tacacs => "TACACS+",
            Proto::Radius => "RADIUS",
        }
    }
}

// ── GET /api/security/aaa ───────────────────────────────────────────────────

fn proto_doc(plat: &mut dyn Platform, proto: Proto) -> anyhow::Result<serde_json::Value> {
    let global = row(plat, CONFIG_DB, proto.global_key());
    let prefix = format!("{}|", proto.server_table());
    let mut servers = Vec::new();
    for key in plat.scan(CONFIG_DB, &format!("{}|*", proto.server_table()))? {
        let Some(address) = key_suffix(&key, &prefix) else { continue };
        let r = row(plat, CONFIG_DB, &key);
        servers.push(json!({
            "address": address,
            "priority": parse_num(field(&r, "priority")),
            "port": parse_num(field(&r, proto.port_field())),
            "timeout": parse_num(field(&r, "timeout")),
            "key_set": r.contains_key("passkey"),
        }));
    }
    servers.sort_by(|a, b| a["address"].as_str().cmp(&b["address"].as_str()));
    Ok(json!({
        "auth_type": field(&global, "auth_type").unwrap_or("pap"),
        "timeout": parse_num(field(&global, "timeout")),
        "global_key_set": global.contains_key("passkey"),
        "servers": servers,
    }))
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let auth = row(plat, CONFIG_DB, "AAA|authentication");
    let login_order: Vec<String> = field(&auth, "login")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_else(|| vec!["local".to_string()]);
    let failthrough = field(&auth, "failthrough")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    Ok(json!({
        "capability": Capability::yes(),
        "login_order": login_order,
        "failthrough": failthrough,
        "tacacs": proto_doc(plat, Proto::Tacacs)?,
        "radius": proto_doc(plat, Proto::Radius)?,
    }))
}

// ── PUT /api/security/aaa/authentication ────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthenticationInput {
    pub login_order: Vec<String>,
    #[serde(default)]
    pub failthrough: bool,
}

pub fn put_authentication(plat: &mut dyn Platform, input: &AuthenticationInput) -> WriteResult {
    let _lock = store::feature_lock("aaa");
    if input.login_order.is_empty() {
        return Err(bad("login_order cannot be empty"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for m in &input.login_order {
        if !matches!(m.as_str(), "local" | "tacacs+" | "radius") {
            return Err(bad(format!("invalid login method {m:?} (local, tacacs+, or radius)")));
        }
        if !seen.insert(m.as_str()) {
            return Err(bad(format!("duplicate login method {m}")));
        }
    }
    // The lockout guard: an order without local can strand the switch when
    // every AAA server is unreachable.
    if !seen.contains("local") {
        return Err(bad("login_order must include \"local\" (lockout guard)"));
    }
    plat.hset(
        CONFIG_DB,
        "AAA|authentication",
        &[
            ("login", &input.login_order.join(",")),
            ("failthrough", if input.failthrough { "True" } else { "False" }),
        ],
    )
    .map_err(WriteError::Redis)
}

// ── shared field validation ─────────────────────────────────────────────────

fn check_auth_type(v: &str) -> std::result::Result<(), String> {
    match v {
        "pap" | "chap" | "mschapv2" | "login" => Ok(()),
        other => Err(format!("invalid auth_type {other:?} (pap, chap, mschapv2, or login)")),
    }
}

fn check_timeout(v: Option<u64>) -> std::result::Result<(), String> {
    match v {
        Some(t) if !(1..=60).contains(&t) => Err(format!("invalid timeout {t} (must be 1-60)")),
        _ => Ok(()),
    }
}

/// A shared secret headed for CONFIG_DB: SONiC caps passkeys at 65
/// characters, printable ASCII without spaces or commas (comma is hostcfgd's
/// own list separator).
fn check_key(key: &str) -> std::result::Result<(), String> {
    if key.is_empty() || key.len() > 65 {
        return Err("invalid key: must be 1-65 characters".to_string());
    }
    if !key.bytes().all(|b| (0x21..0x7f).contains(&b) && b != b',') {
        return Err("invalid key: printable ASCII without spaces or commas".to_string());
    }
    Ok(())
}

/// Apply the write-only key convention to `row_key`: None = leave, "" =
/// clear, otherwise set.
fn apply_key(plat: &mut dyn Platform, row_key: &str, key: Option<&str>) -> WriteResult {
    match key {
        None => Ok(()),
        Some("") => plat.hdel(CONFIG_DB, row_key, &["passkey"]).map_err(WriteError::Redis),
        Some(k) => {
            check_key(k).map_err(bad)?;
            plat.hset(CONFIG_DB, row_key, &[("passkey", k)]).map_err(WriteError::Redis)
        }
    }
}

// ── PUT /api/security/aaa/{tacacs|radius} ───────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GlobalInput {
    pub auth_type: String,
    pub timeout: Option<u64>,
    /// null = unchanged, "" = clear.
    pub key: Option<String>,
}

pub fn put_global(plat: &mut dyn Platform, proto: Proto, input: &GlobalInput) -> WriteResult {
    let _lock = store::feature_lock("aaa");
    check_auth_type(&input.auth_type).map_err(bad)?;
    check_timeout(input.timeout).map_err(bad)?;
    if let Some(key) = input.key.as_deref().filter(|k| !k.is_empty()) {
        check_key(key).map_err(bad)?;
    }
    let row_key = proto.global_key();
    plat.hset(CONFIG_DB, row_key, &[("auth_type", &input.auth_type)])
        .map_err(WriteError::Redis)?;
    match input.timeout {
        Some(t) => plat
            .hset(CONFIG_DB, row_key, &[("timeout", &t.to_string())])
            .map_err(WriteError::Redis)?,
        None => plat.hdel(CONFIG_DB, row_key, &["timeout"]).map_err(WriteError::Redis)?,
    }
    apply_key(plat, row_key, input.key.as_deref())
}

// ── server writes ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ServerCreate {
    pub address: String,
    #[serde(flatten)]
    pub input: ServerInput,
}

#[derive(Debug, Deserialize)]
pub struct ServerInput {
    pub priority: Option<u64>,
    pub port: Option<u64>,
    pub timeout: Option<u64>,
    /// null = unchanged, "" = clear.
    pub key: Option<String>,
}

fn check_server(input: &ServerInput) -> std::result::Result<(), String> {
    if let Some(p) = input.priority {
        if !(1..=64).contains(&p) {
            return Err(format!("invalid priority {p} (must be 1-64)"));
        }
    }
    if let Some(p) = input.port {
        if !(1..=65535).contains(&p) {
            return Err(format!("invalid port {p} (must be 1-65535)"));
        }
    }
    check_timeout(input.timeout)?;
    if let Some(key) = input.key.as_deref().filter(|k| !k.is_empty()) {
        check_key(key)?;
    }
    Ok(())
}

fn check_address(address: &str) -> std::result::Result<(), String> {
    if address.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    // Hostnames are accepted too (hostcfgd resolves them).
    let ok = !address.is_empty()
        && address.len() <= 255
        && address.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!("invalid server address {address:?}"))
    }
}

/// Converge the optional fields (full desired state — null clears).
fn write_server_fields(
    plat: &mut dyn Platform,
    proto: Proto,
    row_key: &str,
    input: &ServerInput,
) -> WriteResult {
    for (f, v) in [
        ("priority", input.priority),
        (proto.port_field(), input.port),
        ("timeout", input.timeout),
    ] {
        match v {
            Some(v) => plat
                .hset(CONFIG_DB, row_key, &[(f, &v.to_string())])
                .map_err(WriteError::Redis)?,
            None => plat.hdel(CONFIG_DB, row_key, &[f]).map_err(WriteError::Redis)?,
        }
    }
    // An otherwise-empty row still needs to exist to register the server.
    if plat.hgetall(CONFIG_DB, row_key).map_err(WriteError::Redis)?.is_empty() {
        plat.hset(CONFIG_DB, row_key, &[("NULL", "NULL")]).map_err(WriteError::Redis)?;
    }
    apply_key(plat, row_key, input.key.as_deref())
}

pub fn create_server(plat: &mut dyn Platform, proto: Proto, create: &ServerCreate) -> WriteResult {
    let _lock = store::feature_lock("aaa");
    check_address(&create.address).map_err(bad)?;
    check_server(&create.input).map_err(bad)?;
    let row_key = format!("{}|{}", proto.server_table(), create.address);
    if plat.exists(CONFIG_DB, &row_key).map_err(WriteError::Redis)? {
        return Err(WriteError::Conflict(format!(
            "{} server {} already exists",
            proto.label(),
            create.address
        )));
    }
    write_server_fields(plat, proto, &row_key, &create.input)
}

pub fn update_server(
    plat: &mut dyn Platform,
    proto: Proto,
    address: &str,
    input: &ServerInput,
) -> WriteResult {
    let _lock = store::feature_lock("aaa");
    check_server(input).map_err(bad)?;
    let row_key = format!("{}|{}", proto.server_table(), address);
    if !plat.exists(CONFIG_DB, &row_key).map_err(WriteError::Redis)? {
        return Err(WriteError::NotFound(format!(
            "no {} server {address}",
            proto.label()
        )));
    }
    write_server_fields(plat, proto, &row_key, input)
}

pub fn delete_server(plat: &mut dyn Platform, proto: Proto, address: &str) -> WriteResult {
    let _lock = store::feature_lock("aaa");
    let row_key = format!("{}|{}", proto.server_table(), address);
    if !plat.exists(CONFIG_DB, &row_key).map_err(WriteError::Redis)? {
        return Err(WriteError::NotFound(format!(
            "no {} server {address}",
            proto.label()
        )));
    }
    plat.del(CONFIG_DB, &row_key).map_err(WriteError::Redis)
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::*;

    fn server(key: Option<&str>) -> ServerInput {
        ServerInput { priority: Some(1), port: Some(49), timeout: None, key: key.map(str::to_string) }
    }

    #[test]
    fn get_never_leaks_passkeys() {
        let mut m = MemPlatform::new();
        m.seed(CONFIG_DB, "AAA|authentication", &[("login", "tacacs+,local"), ("failthrough", "True")]);
        m.seed(CONFIG_DB, "TACPLUS|global", &[("auth_type", "chap"), ("timeout", "10"), ("passkey", "sup3rs3cret")]);
        m.seed(
            CONFIG_DB,
            "TACPLUS_SERVER|10.0.0.20",
            &[("priority", "5"), ("tcp_port", "49"), ("passkey", "s3rv3rs3cret")],
        );
        m.seed(CONFIG_DB, "RADIUS_SERVER|10.0.0.30", &[("auth_port", "1812")]);
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["login_order"], serde_json::json!(["tacacs+", "local"]));
        assert_eq!(doc["failthrough"], true);
        assert_eq!(doc["tacacs"]["auth_type"], "chap");
        assert_eq!(doc["tacacs"]["timeout"], 10);
        assert_eq!(doc["tacacs"]["global_key_set"], true);
        let srv = &doc["tacacs"]["servers"][0];
        assert_eq!(srv["address"], "10.0.0.20");
        assert_eq!(srv["priority"], 5);
        assert_eq!(srv["port"], 49);
        assert_eq!(srv["key_set"], true);
        assert_eq!(doc["radius"]["auth_type"], "pap"); // default
        assert_eq!(doc["radius"]["global_key_set"], false);
        assert_eq!(doc["radius"]["servers"][0]["key_set"], false);
        // The word "s3cret" appears nowhere in the document.
        assert!(!doc.to_string().contains("s3cret"), "{doc}");
        // Defaults with an empty CONFIG_DB.
        let mut bare = MemPlatform::new();
        let doc = get(&mut bare).unwrap();
        assert_eq!(doc["login_order"], serde_json::json!(["local"]));
        assert_eq!(doc["failthrough"], false);
    }

    #[test]
    fn authentication_lockout_guard() {
        let mut m = MemPlatform::new();
        put_authentication(
            &mut m,
            &AuthenticationInput {
                login_order: vec!["tacacs+".into(), "local".into()],
                failthrough: true,
            },
        )
        .unwrap();
        let r = m.row(CONFIG_DB, "AAA|authentication");
        assert_eq!(r.get("login").unwrap(), "tacacs+,local");
        assert_eq!(r.get("failthrough").unwrap(), "True");
        for order in [
            vec![],
            vec!["tacacs+".to_string()],                      // no local
            vec!["radius".to_string(), "kerberos".to_string()], // unknown method
            vec!["local".to_string(), "local".to_string()],   // duplicate
        ] {
            let err = put_authentication(
                &mut m,
                &AuthenticationInput { login_order: order.clone(), failthrough: false },
            )
            .unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{order:?}");
        }
    }

    #[test]
    fn global_put_key_conventions() {
        let mut m = MemPlatform::new();
        m.seed(CONFIG_DB, "TACPLUS|global", &[("passkey", "old")]);
        // key null → unchanged.
        put_global(
            &mut m,
            Proto::Tacacs,
            &GlobalInput { auth_type: "pap".into(), timeout: Some(5), key: None },
        )
        .unwrap();
        let r = m.row(CONFIG_DB, "TACPLUS|global");
        assert_eq!(r.get("passkey").unwrap(), "old");
        assert_eq!(r.get("timeout").unwrap(), "5");
        // key "x" → replaced; timeout null → cleared.
        put_global(
            &mut m,
            Proto::Tacacs,
            &GlobalInput { auth_type: "pap".into(), timeout: None, key: Some("newkey".into()) },
        )
        .unwrap();
        let r = m.row(CONFIG_DB, "TACPLUS|global");
        assert_eq!(r.get("passkey").unwrap(), "newkey");
        assert!(!r.contains_key("timeout"));
        // key "" → cleared.
        put_global(
            &mut m,
            Proto::Tacacs,
            &GlobalInput { auth_type: "pap".into(), timeout: None, key: Some("".into()) },
        )
        .unwrap();
        assert!(!m.row(CONFIG_DB, "TACPLUS|global").contains_key("passkey"));
        // Bad values.
        for input in [
            GlobalInput { auth_type: "kerberos".into(), timeout: None, key: None },
            GlobalInput { auth_type: "pap".into(), timeout: Some(0), key: None },
            GlobalInput { auth_type: "pap".into(), timeout: None, key: Some("has space".into()) },
        ] {
            let err = put_global(&mut m, Proto::Tacacs, &input).unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)));
        }
    }

    #[test]
    fn server_lifecycle_per_proto() {
        let mut m = MemPlatform::new();
        create_server(
            &mut m,
            Proto::Tacacs,
            &ServerCreate { address: "10.0.0.20".into(), input: server(Some("tackey")) },
        )
        .unwrap();
        let r = m.row(CONFIG_DB, "TACPLUS_SERVER|10.0.0.20");
        assert_eq!(r.get("tcp_port").unwrap(), "49");
        assert_eq!(r.get("passkey").unwrap(), "tackey");
        // RADIUS uses auth_port.
        create_server(
            &mut m,
            Proto::Radius,
            &ServerCreate {
                address: "10.0.0.30".into(),
                input: ServerInput { priority: None, port: Some(1812), timeout: Some(3), key: None },
            },
        )
        .unwrap();
        let r = m.row(CONFIG_DB, "RADIUS_SERVER|10.0.0.30");
        assert_eq!(r.get("auth_port").unwrap(), "1812");
        assert!(!r.contains_key("passkey"));
        // Duplicate → 409.
        let err = create_server(
            &mut m,
            Proto::Tacacs,
            &ServerCreate { address: "10.0.0.20".into(), input: server(None) },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));

        // Update: nulls clear fields, key null leaves the secret alone.
        update_server(
            &mut m,
            Proto::Tacacs,
            "10.0.0.20",
            &ServerInput { priority: None, port: None, timeout: Some(10), key: None },
        )
        .unwrap();
        let r = m.row(CONFIG_DB, "TACPLUS_SERVER|10.0.0.20");
        assert!(!r.contains_key("priority"));
        assert!(!r.contains_key("tcp_port"));
        assert_eq!(r.get("timeout").unwrap(), "10");
        assert_eq!(r.get("passkey").unwrap(), "tackey");

        delete_server(&mut m, Proto::Tacacs, "10.0.0.20").unwrap();
        assert!(!m.has_key(CONFIG_DB, "TACPLUS_SERVER|10.0.0.20"));
        let err = delete_server(&mut m, Proto::Tacacs, "10.0.0.20").unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
        let err = update_server(&mut m, Proto::Radius, "10.9.9.9", &server(None)).unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
    }

    #[test]
    fn server_validation() {
        let mut m = MemPlatform::new();
        for (address, input) in [
            ("not a host!", server(None)),
            ("10.0.0.20", ServerInput { priority: Some(0), ..server(None) }),
            ("10.0.0.20", ServerInput { port: Some(0), ..server(None) }),
            ("10.0.0.20", ServerInput { timeout: Some(99), ..server(None) }),
            ("10.0.0.20", server(Some("bad key"))),
        ] {
            let err = create_server(
                &mut m,
                Proto::Tacacs,
                &ServerCreate { address: address.into(), input },
            )
            .unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{address}");
        }
        // Hostname addresses are fine.
        create_server(
            &mut m,
            Proto::Radius,
            &ServerCreate { address: "aaa.example.com".into(), input: server(None) },
        )
        .unwrap();
        assert!(m.has_key(CONFIG_DB, "RADIUS_SERVER|aaa.example.com"));
    }
}
