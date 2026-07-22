//! System configuration for the console's Configure → System pages:
//! general (hostname / timezone / NTP / syslog), the management interface,
//! local users, SNMP, and maintenance (images, config save/backup/restore).
//!
//! CONFIG_DB carries most of it (DEVICE_METADATA, NTP_SERVER, SYSLOG_SERVER,
//! MGMT_INTERFACE, SNMP*, FEATURE) with hostcfgd applying the changes; users
//! are host accounts managed with useradd/usermod/chpasswd (passwords travel
//! on stdin, never argv); maintenance shells out to sonic-installer/config.
//!
//! The management-interface PUT can re-address the very interface the cloud
//! tunnel rides. The CONFIG_DB row writes themselves are instant and the
//! response is already on its way back before hostcfgd re-runs
//! interfaces-config, so the console gets its 200 — after that the tunnel
//! drops and the agent reconnects on the new address.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, field, key_suffix, keys, row, two_parts, Platform};
use super::switching::{parse_num, WriteError, WriteResult};
use super::CONFIG_DB;

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

fn internal(msg: impl Into<String>) -> WriteError {
    WriteError::Internal(msg.into())
}

/// A read-only capability (state visible, edits refused).
fn read_only(reason: impl Into<String>) -> Capability {
    Capability { supported: true, read_only: true, reason: Some(reason.into()) }
}

const META: &str = "DEVICE_METADATA|localhost";

// ── /api/system/general ─────────────────────────────────────────────────────

pub fn get_general(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let meta = row(plat, CONFIG_DB, META);
    let hostname = field(&meta, "hostname")
        .map(str::to_string)
        .or_else(|| plat.read_file("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_default();
    let timezone = field(&meta, "timezone")
        .map(str::to_string)
        .or_else(|| plat.read_file("/etc/timezone").map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Etc/UTC".to_string());
    // IANA names for the picker; [] degrades the console to free-form input.
    let timezones: Vec<String> = plat
        .run("timedatectl", &["list-timezones", "--no-pager"])
        .ok()
        .filter(|o| o.ok)
        .map(|o| o.stdout.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default();
    let mut ntp_servers: Vec<String> = plat
        .scan(CONFIG_DB, "NTP_SERVER|*")?
        .iter()
        .filter_map(|k| key_suffix(k, "NTP_SERVER|"))
        .map(str::to_string)
        .collect();
    ntp_servers.sort();
    let mut syslog_servers = Vec::new();
    for key in plat.scan(CONFIG_DB, "SYSLOG_SERVER|*")? {
        let Some(address) = key_suffix(&key, "SYSLOG_SERVER|") else { continue };
        let r = row(plat, CONFIG_DB, &key);
        syslog_servers.push(json!({
            "address": address,
            "port": parse_num(field(&r, "port")),
        }));
    }
    syslog_servers.sort_by(|a, b| a["address"].as_str().cmp(&b["address"].as_str()));
    Ok(json!({
        "capability": Capability::yes(),
        "hostname": hostname,
        "timezone": timezone,
        "timezones": timezones,
        "ntp_servers": ntp_servers,
        "syslog_servers": syslog_servers,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SyslogServerInput {
    pub address: String,
    pub port: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct GeneralInput {
    pub hostname: String,
    pub timezone: String,
    #[serde(default)]
    pub ntp_servers: Vec<String>,
    #[serde(default)]
    pub syslog_servers: Vec<SyslogServerInput>,
}

fn check_hostname(name: &str) -> std::result::Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!("invalid hostname {name:?} (letters, digits, and dashes; 63 chars max)"))
    }
}

/// A server address usable as a CONFIG_DB key part: IP or hostname shape.
fn check_server_address(addr: &str) -> std::result::Result<(), String> {
    let ok = !addr.is_empty()
        && addr.len() <= 255
        && addr.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:_".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(format!("invalid server address {addr:?}"))
    }
}

pub fn put_general(plat: &mut dyn Platform, input: &GeneralInput) -> WriteResult {
    let _lock = store::feature_lock("system");
    check_hostname(&input.hostname).map_err(bad)?;
    let tz_ok = !input.timezone.is_empty()
        && input.timezone.len() <= 64
        && input.timezone.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_+-".contains(&b));
    if !tz_ok {
        return Err(bad(format!("invalid timezone {:?}", input.timezone)));
    }
    let mut seen = std::collections::BTreeSet::new();
    for s in &input.ntp_servers {
        check_server_address(s).map_err(bad)?;
        if !seen.insert(s.as_str()) {
            return Err(bad(format!("duplicate NTP server {s}")));
        }
    }
    let mut desired_syslog: BTreeMap<&str, Option<u16>> = BTreeMap::new();
    for s in &input.syslog_servers {
        check_server_address(&s.address).map_err(bad)?;
        if s.port == Some(0) {
            return Err(bad("invalid syslog port 0".to_string()));
        }
        if desired_syslog.insert(s.address.as_str(), s.port).is_some() {
            return Err(bad(format!("duplicate syslog server {}", s.address)));
        }
    }

    let cur_ntp = keys(plat, CONFIG_DB, "NTP_SERVER|*");
    let cur_syslog = keys(plat, CONFIG_DB, "SYSLOG_SERVER|*");
    store::apply(plat, |b| {
        b.hset(
            CONFIG_DB,
            META,
            &[("hostname", &input.hostname), ("timezone", &input.timezone)],
        )?;
        for key in &cur_ntp {
            let Some(name) = key_suffix(key, "NTP_SERVER|") else { continue };
            if !input.ntp_servers.iter().any(|s| s == name) {
                b.del(CONFIG_DB, key)?;
            }
        }
        for s in &input.ntp_servers {
            if !cur_ntp.iter().any(|k| key_suffix(k, "NTP_SERVER|") == Some(s)) {
                b.hset(CONFIG_DB, &format!("NTP_SERVER|{s}"), &[("NULL", "NULL")])?;
            }
        }
        for key in &cur_syslog {
            let Some(addr) = key_suffix(key, "SYSLOG_SERVER|") else { continue };
            if !desired_syslog.contains_key(addr) {
                b.del(CONFIG_DB, key)?;
            }
        }
        for (addr, port) in &desired_syslog {
            let key = format!("SYSLOG_SERVER|{addr}");
            match port {
                Some(p) => b.hset(CONFIG_DB, &key, &[("port", &p.to_string())])?,
                None => {
                    b.hset(CONFIG_DB, &key, &[("NULL", "NULL")])?;
                    b.hdel(CONFIG_DB, &key, &["port"])?;
                }
            }
        }
        Ok(())
    })
    .map_err(WriteError::Redis)?;
    // Best-effort immediate apply; hostcfgd picks the CONFIG_DB values up on
    // images that consume them.
    let _ = plat.run("timedatectl", &["set-timezone", &input.timezone]);
    Ok(())
}

// ── /api/system/management ──────────────────────────────────────────────────

const MGMT_IFACE: &str = "eth0";

/// The MGMT_INTERFACE IP rows for eth0, (cidr, row-key) sorted v4-first.
fn mgmt_rows(plat: &mut dyn Platform) -> anyhow::Result<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = plat
        .scan(CONFIG_DB, &format!("MGMT_INTERFACE|{MGMT_IFACE}|*"))?
        .into_iter()
        .filter_map(|k| {
            two_parts(&k, "MGMT_INTERFACE|").map(|(_, cidr)| (cidr.to_string(), k.clone()))
        })
        .collect();
    out.sort_by_key(|(cidr, _)| (cidr.contains(':'), cidr.clone()));
    Ok(out)
}

pub fn get_management(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let mac = plat
        .read_file(&format!("/sys/class/net/{MGMT_IFACE}/address"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let capability = if mac.is_some() {
        Capability::yes()
    } else {
        read_only(format!("this platform has no {MGMT_IFACE} management interface"))
    };
    let oper = plat
        .read_file(&format!("/sys/class/net/{MGMT_IFACE}/operstate"))
        .map(|s| s.trim().to_string())
        .filter(|s| s == "up" || s == "down")
        .unwrap_or_else(|| "unknown".to_string());
    let rows = mgmt_rows(plat)?;
    let (ip_address, gateway) = match rows.first() {
        Some((cidr, key)) => {
            let r = row(plat, CONFIG_DB, key);
            (Some(cidr.clone()), field(&r, "gwaddr").map(str::to_string))
        }
        None => (None, None),
    };
    let mgmt_vrf = field(&row(plat, CONFIG_DB, "MGMT_VRF_CONFIG|vrf_global"), "mgmtVrfEnabled")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    Ok(json!({
        "capability": capability,
        "interface_name": MGMT_IFACE,
        "dhcp": rows.is_empty(),
        "ip_address": ip_address,
        "gateway": gateway,
        "mgmt_vrf_enabled": mgmt_vrf,
        "mac_address": mac,
        "oper_status": oper,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ManagementInput {
    pub dhcp: bool,
    pub ip_address: Option<String>,
    pub gateway: Option<String>,
}

pub fn put_management(plat: &mut dyn Platform, input: &ManagementInput) -> WriteResult {
    let _lock = store::feature_lock("system");
    let rows = mgmt_rows(plat).map_err(WriteError::Redis)?;
    if input.dhcp {
        // Back to DHCP: no MGMT_INTERFACE rows at all.
        for (_, key) in &rows {
            plat.del(CONFIG_DB, key).map_err(WriteError::Redis)?;
        }
        plat.del(CONFIG_DB, &format!("MGMT_INTERFACE|{MGMT_IFACE}"))
            .map_err(WriteError::Redis)?;
        return Ok(());
    }
    let Some(cidr) = input.ip_address.as_deref() else {
        return Err(bad("a static management config needs ip_address"));
    };
    let parse_cidr = |s: &str| -> Option<std::net::IpAddr> {
        let (ip, len) = s.split_once('/')?;
        let ip: std::net::IpAddr = ip.parse().ok()?;
        let len: u8 = len.parse().ok()?;
        (len <= if ip.is_ipv4() { 32 } else { 128 }).then_some(ip)
    };
    let Some(ip) = parse_cidr(cidr) else {
        return Err(bad(format!("invalid ip_address {cidr:?} (expected CIDR)")));
    };
    if let Some(gw) = input.gateway.as_deref() {
        let ok = gw.parse::<std::net::IpAddr>().map(|g| g.is_ipv4() == ip.is_ipv4());
        if ok != Ok(true) {
            return Err(bad(format!("invalid gateway {gw:?}")));
        }
    }
    store::apply(plat, |b| {
        for (cur, key) in &rows {
            if cur != cidr {
                b.del(CONFIG_DB, key)?;
            }
        }
        let key = format!("MGMT_INTERFACE|{MGMT_IFACE}|{cidr}");
        match input.gateway.as_deref() {
            Some(gw) => b.hset(CONFIG_DB, &key, &[("gwaddr", gw)])?,
            None => {
                b.hset(CONFIG_DB, &key, &[("NULL", "NULL")])?;
                b.hdel(CONFIG_DB, &key, &["gwaddr"])?;
            }
        }
        Ok(())
    })
    .map_err(WriteError::Redis)
}

// ── /api/system/users ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UserDoc {
    pub name: String,
    pub role: &'static str,
    pub builtin: bool,
}

/// Parse /etc/passwd + /etc/group into the contract's user list: human
/// accounts (uid 1000..65534, login shell), role from sudo/admin group
/// membership, the image's stock uid-1000 "admin" account marked builtin.
/// Pure.
pub fn parse_users(passwd: &str, group: &str) -> Vec<UserDoc> {
    let mut admins: Vec<&str> = Vec::new();
    for line in group.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if let [name, _, _, members] = parts.as_slice() {
            if *name == "sudo" || *name == "admin" {
                admins.extend(members.split(',').map(str::trim).filter(|m| !m.is_empty()));
            }
        }
    }
    let mut users = Vec::new();
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        let [name, _, uid, _gid, _gecos, _home, shell] = parts.as_slice() else { continue };
        let Ok(uid) = uid.parse::<u32>() else { continue };
        if !(1000..65534).contains(&uid) {
            continue;
        }
        if shell.ends_with("nologin") || shell.ends_with("false") {
            continue;
        }
        users.push(UserDoc {
            name: name.to_string(),
            role: if admins.contains(name) { "admin" } else { "operator" },
            builtin: uid == 1000 || *name == "admin",
        });
    }
    users.sort_by(|a, b| a.name.cmp(&b.name));
    users
}

fn read_users(plat: &mut dyn Platform) -> Option<Vec<UserDoc>> {
    let passwd = plat.read_file("/etc/passwd")?;
    let group = plat.read_file("/etc/group").unwrap_or_default();
    Some(parse_users(&passwd, &group))
}

pub fn get_users(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    match read_users(plat) {
        Some(users) => Ok(json!({ "capability": Capability::yes(), "users": users })),
        None => Ok(json!({
            "capability": read_only("cannot read the system account database"),
            "users": [],
        })),
    }
}

#[derive(Debug, Deserialize)]
pub struct UserCreate {
    pub name: String,
    pub role: Role,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct UserUpdate {
    pub role: Role,
    /// null = unchanged.
    pub password: Option<String>,
}

fn check_username(name: &str) -> std::result::Result<(), String> {
    let mut bytes = name.bytes();
    let ok = name.len() <= 32
        && matches!(bytes.next(), Some(b) if b.is_ascii_lowercase() || b == b'_')
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid username {name:?} (lowercase letters, digits, _ and -; 32 chars max)"
        ))
    }
}

fn check_password(password: &str) -> std::result::Result<(), String> {
    if password.is_empty() || password.len() > 128 {
        return Err("password must be 1-128 characters".to_string());
    }
    if password.contains('\n') || password.contains(':') {
        return Err("password cannot contain newlines or colons".to_string());
    }
    Ok(())
}

fn users_or_fail(plat: &mut dyn Platform) -> std::result::Result<Vec<UserDoc>, WriteError> {
    read_users(plat).ok_or_else(|| internal("cannot read the system account database"))
}

fn run_ok(plat: &mut dyn Platform, program: &str, args: &[&str]) -> WriteResult {
    let out = plat
        .run(program, args)
        .map_err(|e| internal(format!("{program}: {e:#}")))?;
    if !out.ok {
        return Err(internal(format!(
            "{program} failed: {}",
            if out.stderr.trim().is_empty() { out.stdout.trim() } else { out.stderr.trim() }
        )));
    }
    Ok(())
}

fn set_password(plat: &mut dyn Platform, name: &str, password: &str) -> WriteResult {
    let out = plat
        .run_input("chpasswd", &[], &format!("{name}:{password}\n"))
        .map_err(|e| internal(format!("chpasswd: {e:#}")))?;
    if !out.ok {
        return Err(internal(format!("chpasswd failed: {}", out.stderr.trim())));
    }
    Ok(())
}

/// The admin-capable groups this image actually has (sudo always on SONiC;
/// docker for CLI access to the containers; admin on enterprise builds).
fn admin_groups(plat: &mut dyn Platform) -> Vec<&'static str> {
    let group = plat.read_file("/etc/group").unwrap_or_default();
    ["sudo", "docker", "admin"]
        .into_iter()
        .filter(|g| group.lines().any(|l| l.split(':').next() == Some(g)))
        .collect()
}

fn apply_role(plat: &mut dyn Platform, name: &str, role: Role) -> WriteResult {
    let groups = admin_groups(plat);
    match role {
        Role::Admin => {
            if !groups.is_empty() {
                run_ok(plat, "usermod", &["-aG", &groups.join(","), name])?;
            }
        }
        Role::Operator => {
            for g in groups {
                // gpasswd -d fails when the user isn't a member — harmless.
                let _ = plat.run("gpasswd", &["-d", name, g]);
            }
        }
    }
    Ok(())
}

pub fn create_user(plat: &mut dyn Platform, input: &UserCreate) -> WriteResult {
    let _lock = store::feature_lock("system");
    check_username(&input.name).map_err(bad)?;
    check_password(&input.password).map_err(bad)?;
    let passwd = plat.read_file("/etc/passwd").unwrap_or_default();
    if passwd.lines().any(|l| l.split(':').next() == Some(input.name.as_str())) {
        return Err(WriteError::Conflict(format!("user {} already exists", input.name)));
    }
    run_ok(plat, "useradd", &["-m", "-s", "/bin/bash", &input.name])?;
    apply_role(plat, &input.name, input.role)?;
    set_password(plat, &input.name, &input.password)
}

pub fn update_user(plat: &mut dyn Platform, name: &str, input: &UserUpdate) -> WriteResult {
    let _lock = store::feature_lock("system");
    let users = users_or_fail(plat)?;
    let Some(user) = users.iter().find(|u| u.name == name) else {
        return Err(WriteError::NotFound(format!("no such user {name}")));
    };
    if let Some(password) = &input.password {
        check_password(password).map_err(bad)?;
    }
    let demoting = user.role == "admin" && input.role == Role::Operator;
    if demoting && users.iter().filter(|u| u.role == "admin").count() <= 1 {
        return Err(WriteError::Conflict(format!(
            "{name} is the last admin; promote another user first"
        )));
    }
    apply_role(plat, name, input.role)?;
    if let Some(password) = &input.password {
        set_password(plat, name, password)?;
    }
    Ok(())
}

pub fn delete_user(plat: &mut dyn Platform, name: &str) -> WriteResult {
    let _lock = store::feature_lock("system");
    let users = users_or_fail(plat)?;
    let Some(user) = users.iter().find(|u| u.name == name) else {
        return Err(WriteError::NotFound(format!("no such user {name}")));
    };
    if user.builtin {
        return Err(WriteError::Conflict(format!(
            "{name} is the image's built-in account and cannot be deleted"
        )));
    }
    if user.role == "admin" && users.iter().filter(|u| u.role == "admin").count() <= 1 {
        return Err(WriteError::Conflict(format!(
            "{name} is the last admin; promote another user first"
        )));
    }
    run_ok(plat, "userdel", &["-r", name])
}

// ── /api/system/snmp ────────────────────────────────────────────────────────

fn snmp_capability(plat: &mut dyn Platform) -> Capability {
    let p = probe::current(plat);
    if p.has_feature("snmp") || p.docker_running("snmp") {
        Capability::yes()
    } else {
        Capability::no("this image was built without the snmp feature")
    }
}

pub fn get_snmp(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let capability = snmp_capability(plat);
    let enabled = probe::current(plat).feature_enabled("snmp");
    let location = field(&row(plat, CONFIG_DB, "SNMP|LOCATION"), "Location").map(str::to_string);
    let contact = field(&row(plat, CONFIG_DB, "SNMP|CONTACT"), "Contact").map(str::to_string);
    let mut communities = Vec::new();
    for key in plat.scan(CONFIG_DB, "SNMP_COMMUNITY|*")? {
        let Some(name) = key_suffix(&key, "SNMP_COMMUNITY|") else { continue };
        let r = row(plat, CONFIG_DB, &key);
        let access = match field(&r, "TYPE").map(str::to_ascii_uppercase).as_deref() {
            Some("RW") => "rw",
            _ => "ro",
        };
        communities.push(json!({ "name": name, "access": access }));
    }
    communities.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(json!({
        "capability": capability,
        "enabled": enabled,
        "location": location,
        "contact": contact,
        "communities": communities,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CommunityInput {
    pub name: String,
    pub access: String,
}

#[derive(Debug, Deserialize)]
pub struct SnmpInput {
    pub enabled: bool,
    pub location: Option<String>,
    pub contact: Option<String>,
    #[serde(default)]
    pub communities: Vec<CommunityInput>,
}

pub fn put_snmp(plat: &mut dyn Platform, input: &SnmpInput) -> WriteResult {
    let _lock = store::feature_lock("system");
    if !snmp_capability(plat).supported {
        return Err(WriteError::Conflict(
            "this image was built without the snmp feature".to_string(),
        ));
    }
    let mut desired: BTreeMap<&str, &str> = BTreeMap::new();
    for c in &input.communities {
        let ok = !c.name.is_empty()
            && c.name.len() <= 32
            && c.name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(bad(format!("invalid community name {:?}", c.name)));
        }
        let access = match c.access.as_str() {
            "ro" => "RO",
            "rw" => "RW",
            other => return Err(bad(format!("invalid access {other:?} (ro or rw)"))),
        };
        if desired.insert(c.name.as_str(), access).is_some() {
            return Err(bad(format!("duplicate community {}", c.name)));
        }
    }
    for (what, v) in [("location", &input.location), ("contact", &input.contact)] {
        if let Some(v) = v {
            if v.is_empty() || v.len() > 255 || v.bytes().any(|b| !(0x20..0x7f).contains(&b)) {
                return Err(bad(format!("invalid {what}: printable ASCII, 255 chars max")));
            }
        }
    }
    let cur = keys(plat, CONFIG_DB, "SNMP_COMMUNITY|*");
    store::apply(plat, |b| {
        b.hset(
            CONFIG_DB,
            "FEATURE|snmp",
            &[("state", if input.enabled { "enabled" } else { "disabled" })],
        )?;
        match &input.location {
            Some(v) => b.hset(CONFIG_DB, "SNMP|LOCATION", &[("Location", v)])?,
            None => b.del(CONFIG_DB, "SNMP|LOCATION")?,
        }
        match &input.contact {
            Some(v) => b.hset(CONFIG_DB, "SNMP|CONTACT", &[("Contact", v)])?,
            None => b.del(CONFIG_DB, "SNMP|CONTACT")?,
        }
        for key in &cur {
            let Some(name) = key_suffix(key, "SNMP_COMMUNITY|") else { continue };
            if !desired.contains_key(name) {
                b.del(CONFIG_DB, key)?;
            }
        }
        for (name, access) in &desired {
            b.hset(CONFIG_DB, &format!("SNMP_COMMUNITY|{name}"), &[("TYPE", access)])?;
        }
        Ok(())
    })
    .map_err(WriteError::Redis)?;
    // The FEATURE state may have changed what runs — re-detect next probe.
    probe::invalidate();
    Ok(())
}

// ── /api/system/maintenance ─────────────────────────────────────────────────

/// Parse `sonic-installer list` ("Current: …\nNext: …\nAvailable:\n…"). Pure.
pub fn parse_installer_list(text: &str) -> (Option<String>, Option<String>, Vec<String>) {
    let mut current = None;
    let mut next = None;
    let mut available = Vec::new();
    let mut in_available = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Current:") {
            current = Some(v.trim().to_string()).filter(|s| !s.is_empty());
        } else if let Some(v) = line.strip_prefix("Next:") {
            next = Some(v.trim().to_string()).filter(|s| !s.is_empty());
        } else if line == "Available:" {
            in_available = true;
        } else if in_available && !line.is_empty() {
            available.push(line.to_string());
        }
    }
    (current, next, available)
}

/// Epoch seconds → RFC 3339 UTC ("2026-07-22T14:00:00Z"). Pure (Howard
/// Hinnant's civil-from-days; a chrono dependency is not worth one field).
pub fn rfc3339(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

pub fn get_maintenance(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let (current, next, available) = plat
        .run("sonic-installer", &["list"])
        .ok()
        .filter(|o| o.ok)
        .map(|o| parse_installer_list(&o.stdout))
        .unwrap_or_default();
    let last_config_save = plat
        .run("stat", &["-c", "%Y", "/etc/sonic/config_db.json"])
        .ok()
        .filter(|o| o.ok)
        .and_then(|o| o.stdout.trim().parse::<i64>().ok())
        .map(rfc3339);
    let uptime_seconds = plat
        .read_file("/proc/uptime")
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse::<f64>().ok()))
        .map(|v| v as u64);
    Ok(json!({
        "capability": Capability::yes(),
        "current_image": current,
        "next_image": next,
        "available_images": available,
        "last_config_save": last_config_save,
        "uptime_seconds": uptime_seconds,
    }))
}

pub fn save_config(plat: &mut dyn Platform) -> WriteResult {
    let _lock = store::feature_lock("system");
    run_ok(plat, "config", &["save", "-y"])
}

#[derive(Debug, Deserialize)]
pub struct ImageInput {
    pub image: String,
}

pub fn set_next_image(plat: &mut dyn Platform, input: &ImageInput) -> WriteResult {
    let _lock = store::feature_lock("system");
    let image = input.image.trim();
    if image.is_empty() || image.bytes().any(|b| b.is_ascii_whitespace() || b < 0x20) {
        return Err(bad(format!("invalid image name {:?}", input.image)));
    }
    let out = plat
        .run("sonic-installer", &["set-next-boot", image])
        .map_err(|e| internal(format!("sonic-installer: {e:#}")))?;
    if !out.ok {
        return Err(WriteError::Unprocessable(format!(
            "sonic-installer set-next-boot failed: {}",
            if out.stderr.trim().is_empty() { out.stdout.trim() } else { out.stderr.trim() }
        )));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct UrlInput {
    pub url: String,
}

/// POST /api/system/maintenance/install-image — long-running; the caller
/// awaits sonic-installer to completion before responding.
pub fn install_image(plat: &mut dyn Platform, input: &UrlInput) -> WriteResult {
    let _lock = store::feature_lock("system");
    let url = input.url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://"))
        || url.bytes().any(|b| b.is_ascii_whitespace() || b < 0x20)
    {
        return Err(bad(format!("invalid image url {:?} (http(s) only)", input.url)));
    }
    let out = plat
        .run("sonic-installer", &["install", "-y", url])
        .map_err(|e| internal(format!("sonic-installer: {e:#}")))?;
    if !out.ok {
        return Err(WriteError::Unprocessable(format!(
            "sonic-installer install failed: {}",
            if out.stderr.trim().is_empty() { out.stdout.trim() } else { out.stderr.trim() }
        )));
    }
    Ok(())
}

/// GET /api/system/maintenance/backup — the raw config_db.json content.
pub fn backup(plat: &mut dyn Platform) -> std::result::Result<String, WriteError> {
    plat.read_file("/etc/sonic/config_db.json")
        .ok_or_else(|| WriteError::NotFound("/etc/sonic/config_db.json does not exist".into()))
}

#[derive(Debug, Deserialize)]
pub struct RestoreInput {
    pub config: serde_json::Value,
}

pub fn restore(plat: &mut dyn Platform, input: &RestoreInput) -> WriteResult {
    let _lock = store::feature_lock("system");
    // Plausibility gate: a CONFIG_DB dump is an object of TABLE → rows and
    // always carries DEVICE_METADATA. Anything else would brick the switch
    // on reload.
    let Some(tables) = input.config.as_object() else {
        return Err(bad("config must be a CONFIG_DB object (table → entries)"));
    };
    if !tables.contains_key("DEVICE_METADATA") {
        return Err(WriteError::Unprocessable(
            "this does not look like a CONFIG_DB dump (no DEVICE_METADATA table)".to_string(),
        ));
    }
    if tables.values().any(|v| !v.is_object()) {
        return Err(WriteError::Unprocessable(
            "this does not look like a CONFIG_DB dump (non-object table)".to_string(),
        ));
    }
    let text = serde_json::to_string_pretty(&input.config)
        .map_err(|e| internal(format!("serialize config: {e}")))?;
    plat.write_file("/etc/sonic/config_db.json", &text)
        .map_err(|e| internal(format!("{e:#}")))?;
    run_ok(plat, "config", &["reload", "-y"])
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::super::store::CmdOutput;
    use super::*;

    #[test]
    fn general_get_reads_config_db() {
        let mut m = MemPlatform::new();
        m.seed(CONFIG_DB, META, &[("hostname", "leaf1"), ("timezone", "America/New_York")]);
        m.seed(CONFIG_DB, "NTP_SERVER|pool.ntp.org", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "SYSLOG_SERVER|10.0.0.50", &[("port", "5514")]);
        m.seed(CONFIG_DB, "SYSLOG_SERVER|10.0.0.51", &[("NULL", "NULL")]);
        m.on_cmd(
            &["timedatectl", "list-timezones"],
            CmdOutput { ok: true, stdout: "Etc/UTC\nAmerica/New_York\n".into(), stderr: String::new() },
        );
        let doc = get_general(&mut m).unwrap();
        assert_eq!(doc["hostname"], "leaf1");
        assert_eq!(doc["timezone"], "America/New_York");
        assert_eq!(doc["timezones"], json!(["Etc/UTC", "America/New_York"]));
        assert_eq!(doc["ntp_servers"], json!(["pool.ntp.org"]));
        assert_eq!(doc["syslog_servers"][0]["port"], 5514);
        assert_eq!(doc["syslog_servers"][1]["port"], serde_json::Value::Null);
    }

    #[test]
    fn general_put_diffs_server_lists() {
        let mut m = MemPlatform::new();
        m.seed(CONFIG_DB, "NTP_SERVER|old.ntp.org", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "NTP_SERVER|keep.ntp.org", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "SYSLOG_SERVER|10.0.0.50", &[("port", "514")]);
        put_general(
            &mut m,
            &GeneralInput {
                hostname: "leaf1".into(),
                timezone: "Etc/UTC".into(),
                ntp_servers: vec!["keep.ntp.org".into(), "new.ntp.org".into()],
                syslog_servers: vec![SyslogServerInput { address: "10.0.0.60".into(), port: None }],
            },
        )
        .unwrap();
        assert!(!m.has_key(CONFIG_DB, "NTP_SERVER|old.ntp.org"));
        assert!(m.has_key(CONFIG_DB, "NTP_SERVER|new.ntp.org"));
        assert!(!m.has_key(CONFIG_DB, "SYSLOG_SERVER|10.0.0.50"));
        assert!(m.has_key(CONFIG_DB, "SYSLOG_SERVER|10.0.0.60"));
        assert_eq!(m.row(CONFIG_DB, META).get("hostname").unwrap(), "leaf1");
        // The kept NTP row was never touched.
        assert!(!m.log.iter().any(|l| l.contains("keep.ntp.org")), "{:?}", m.log);
        // Best-effort immediate timezone apply.
        assert!(m.log.iter().any(|l| l.contains("timedatectl set-timezone Etc/UTC")));
    }

    #[test]
    fn general_put_validation() {
        let mut m = MemPlatform::new();
        let base = || GeneralInput {
            hostname: "leaf1".into(),
            timezone: "Etc/UTC".into(),
            ntp_servers: vec![],
            syslog_servers: vec![],
        };
        for input in [
            GeneralInput { hostname: "-bad".into(), ..base() },
            GeneralInput { hostname: "".into(), ..base() },
            GeneralInput { timezone: "Etc UTC".into(), ..base() },
            GeneralInput { ntp_servers: vec!["bad server".into()], ..base() },
            GeneralInput { ntp_servers: vec!["a.b".into(), "a.b".into()], ..base() },
            GeneralInput {
                syslog_servers: vec![SyslogServerInput { address: "10.0.0.1|x".into(), port: None }],
                ..base()
            },
        ] {
            let err = put_general(&mut m, &input).unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)));
        }
    }

    #[test]
    fn management_get_static_and_dhcp() {
        let mut m = MemPlatform::new();
        m.seed_file("/sys/class/net/eth0/address", "aa:bb:cc:dd:ee:ff\n");
        m.seed_file("/sys/class/net/eth0/operstate", "up\n");
        // DHCP: no MGMT_INTERFACE rows.
        let doc = get_management(&mut m).unwrap();
        assert_eq!(doc["capability"]["read_only"], false);
        assert_eq!(doc["dhcp"], true);
        assert_eq!(doc["ip_address"], serde_json::Value::Null);
        assert_eq!(doc["mac_address"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(doc["oper_status"], "up");
        // Static, v4 preferred over v6.
        m.seed(CONFIG_DB, "MGMT_INTERFACE|eth0|fd00::5/64", &[("NULL", "NULL")]);
        m.seed(CONFIG_DB, "MGMT_INTERFACE|eth0|10.0.10.5/24", &[("gwaddr", "10.0.10.1")]);
        let doc = get_management(&mut m).unwrap();
        assert_eq!(doc["dhcp"], false);
        assert_eq!(doc["ip_address"], "10.0.10.5/24");
        assert_eq!(doc["gateway"], "10.0.10.1");
        // No eth0 → read-only.
        let mut bare = MemPlatform::new();
        let doc = get_management(&mut bare).unwrap();
        assert_eq!(doc["capability"]["read_only"], true);
    }

    #[test]
    fn management_put_static_then_dhcp() {
        let mut m = MemPlatform::new();
        put_management(
            &mut m,
            &ManagementInput {
                dhcp: false,
                ip_address: Some("10.0.10.5/24".into()),
                gateway: Some("10.0.10.1".into()),
            },
        )
        .unwrap();
        assert_eq!(
            m.row(CONFIG_DB, "MGMT_INTERFACE|eth0|10.0.10.5/24").get("gwaddr").unwrap(),
            "10.0.10.1"
        );
        // Re-address: the old row goes away.
        put_management(
            &mut m,
            &ManagementInput { dhcp: false, ip_address: Some("10.0.20.5/24".into()), gateway: None },
        )
        .unwrap();
        assert!(!m.has_key(CONFIG_DB, "MGMT_INTERFACE|eth0|10.0.10.5/24"));
        assert!(m.has_key(CONFIG_DB, "MGMT_INTERFACE|eth0|10.0.20.5/24"));
        // Back to DHCP: nothing left.
        put_management(&mut m, &ManagementInput { dhcp: true, ip_address: None, gateway: None })
            .unwrap();
        assert!(!m.has_key(CONFIG_DB, "MGMT_INTERFACE|eth0|10.0.20.5/24"));
        // Validation.
        for input in [
            ManagementInput { dhcp: false, ip_address: None, gateway: None },
            ManagementInput { dhcp: false, ip_address: Some("10.0.0.5".into()), gateway: None },
            ManagementInput {
                dhcp: false,
                ip_address: Some("10.0.0.5/24".into()),
                gateway: Some("fd00::1".into()), // family mismatch
            },
        ] {
            let err = put_management(&mut m, &input).unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)));
        }
    }

    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash\n\
admin:x:1000:1000::/home/admin:/bin/bash\n\
cody:x:1001:1001::/home/cody:/bin/bash\n\
viewer:x:1002:1002::/home/viewer:/bin/bash\n\
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin\n";
    const GROUP: &str = "sudo:x:27:admin,cody\ndocker:x:999:admin,cody\nusers:x:100:\n";

    fn user_platform() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/passwd", PASSWD);
        m.seed_file("/etc/group", GROUP);
        m
    }

    #[test]
    fn users_parse_roles_and_builtin() {
        let users = parse_users(PASSWD, GROUP);
        assert_eq!(users.len(), 3); // root and sshd filtered out
        let by_name = |n: &str| users.iter().find(|u| u.name == n).unwrap();
        assert_eq!(by_name("admin").role, "admin");
        assert!(by_name("admin").builtin);
        assert_eq!(by_name("cody").role, "admin");
        assert!(!by_name("cody").builtin);
        assert_eq!(by_name("viewer").role, "operator");
    }

    #[test]
    fn user_create_update_delete() {
        let mut m = user_platform();
        create_user(
            &mut m,
            &UserCreate { name: "newop".into(), role: Role::Admin, password: "hunter2".into() },
        )
        .unwrap();
        assert!(m.log.iter().any(|l| l == "RUN useradd -m -s /bin/bash newop"), "{:?}", m.log);
        assert!(m.log.iter().any(|l| l == "RUN usermod -aG sudo,docker newop"), "{:?}", m.log);
        // The password went via stdin, never argv.
        assert!(m.log.iter().all(|l| !l.contains("hunter2")), "{:?}", m.log);
        assert_eq!(m.stdins, vec!["newop:hunter2\n"]);
        // Duplicate → 409.
        let err = create_user(
            &mut m,
            &UserCreate { name: "cody".into(), role: Role::Operator, password: "x".into() },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));

        // Demote cody (admin remains) — groups drop, password unchanged.
        m.log.clear();
        m.stdins.clear();
        update_user(&mut m, "cody", &UserUpdate { role: Role::Operator, password: None }).unwrap();
        assert!(m.log.iter().any(|l| l == "RUN gpasswd -d cody sudo"), "{:?}", m.log);
        assert!(m.stdins.is_empty());

        // viewer deletes fine; admin (builtin) never does.
        delete_user(&mut m, "viewer").unwrap();
        assert!(m.log.iter().any(|l| l == "RUN userdel -r viewer"), "{:?}", m.log);
        let err = delete_user(&mut m, "admin").unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
        let err = delete_user(&mut m, "ghost").unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
    }

    #[test]
    fn last_admin_is_protected() {
        let mut m = MemPlatform::new();
        m.seed_file("/etc/passwd", "solo:x:1001:1001::/home/solo:/bin/bash\n");
        m.seed_file("/etc/group", "sudo:x:27:solo\n");
        let err =
            update_user(&mut m, "solo", &UserUpdate { role: Role::Operator, password: None })
                .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
        let err = delete_user(&mut m, "solo").unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
        // A role-preserving password change is fine.
        update_user(&mut m, "solo", &UserUpdate { role: Role::Admin, password: Some("pw".into()) })
            .unwrap();
        assert_eq!(m.stdins, vec!["solo:pw\n"]);
    }

    #[test]
    fn username_and_password_validation() {
        let mut m = user_platform();
        for name in ["", "Caps", "1num", "way-too-long-a-name-for-a-unix-account", "a b"] {
            let err = create_user(
                &mut m,
                &UserCreate { name: name.into(), role: Role::Operator, password: "x".into() },
            )
            .unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{name}");
        }
        for password in ["", "with:colon", "with\nnewline"] {
            let err = create_user(
                &mut m,
                &UserCreate { name: "okname".into(), role: Role::Operator, password: password.into() },
            )
            .unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{password:?}");
        }
    }

    #[test]
    fn snmp_get_and_put() {
        let mut m = MemPlatform::new();
        m.seed(CONFIG_DB, "FEATURE|snmp", &[("state", "enabled")]);
        m.seed(CONFIG_DB, "SNMP|LOCATION", &[("Location", "rack 4")]);
        m.seed(CONFIG_DB, "SNMP_COMMUNITY|public", &[("TYPE", "RO")]);
        m.seed(CONFIG_DB, "SNMP_COMMUNITY|old", &[("TYPE", "RW")]);
        let doc = get_snmp(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["enabled"], true);
        assert_eq!(doc["location"], "rack 4");
        assert_eq!(doc["contact"], serde_json::Value::Null);
        assert_eq!(doc["communities"][1]["name"], "public");
        assert_eq!(doc["communities"][1]["access"], "ro");

        put_snmp(
            &mut m,
            &SnmpInput {
                enabled: false,
                location: None,
                contact: Some("noc@example.com".into()),
                communities: vec![CommunityInput { name: "public".into(), access: "rw".into() }],
            },
        )
        .unwrap();
        assert_eq!(m.row(CONFIG_DB, "FEATURE|snmp").get("state").unwrap(), "disabled");
        assert!(!m.has_key(CONFIG_DB, "SNMP|LOCATION"));
        assert_eq!(m.row(CONFIG_DB, "SNMP|CONTACT").get("Contact").unwrap(), "noc@example.com");
        assert!(!m.has_key(CONFIG_DB, "SNMP_COMMUNITY|old"));
        assert_eq!(m.row(CONFIG_DB, "SNMP_COMMUNITY|public").get("TYPE").unwrap(), "RW");

        // No snmp feature at all → unsupported.
        let mut bare = MemPlatform::new();
        let doc = get_snmp(&mut bare).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        let err = put_snmp(
            &mut bare,
            &SnmpInput { enabled: true, location: None, contact: None, communities: vec![] },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
    }

    #[test]
    fn maintenance_get_parses_installer_and_uptime() {
        let mut m = MemPlatform::new();
        m.on_cmd(
            &["sonic-installer", "list"],
            CmdOutput {
                ok: true,
                stdout: "Current: SONiC-OS-202311.1\nNext: SONiC-OS-202405.2\nAvailable:\nSONiC-OS-202311.1\nSONiC-OS-202405.2\n".into(),
                stderr: String::new(),
            },
        );
        m.on_cmd(
            &["stat", "-c", "%Y", "/etc/sonic/config_db.json"],
            CmdOutput { ok: true, stdout: "1753192800\n".into(), stderr: String::new() },
        );
        m.seed_file("/proc/uptime", "12345.67 23456.78\n");
        let doc = get_maintenance(&mut m).unwrap();
        assert_eq!(doc["current_image"], "SONiC-OS-202311.1");
        assert_eq!(doc["next_image"], "SONiC-OS-202405.2");
        assert_eq!(doc["available_images"], json!(["SONiC-OS-202311.1", "SONiC-OS-202405.2"]));
        assert_eq!(doc["last_config_save"], "2025-07-22T14:00:00Z");
        assert_eq!(doc["uptime_seconds"], 12345);
        // Everything degrades to null/[] when the tools are missing.
        let mut bare = MemPlatform::new();
        bare.on_cmd(&["sonic-installer"], CmdOutput { ok: false, ..Default::default() });
        bare.on_cmd(&["stat"], CmdOutput { ok: false, ..Default::default() });
        let doc = get_maintenance(&mut bare).unwrap();
        assert_eq!(doc["current_image"], serde_json::Value::Null);
        assert_eq!(doc["available_images"], json!([]));
        assert_eq!(doc["uptime_seconds"], serde_json::Value::Null);
    }

    #[test]
    fn rfc3339_epochs() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1753192800), "2025-07-22T14:00:00Z");
        assert_eq!(rfc3339(951782400), "2000-02-29T00:00:00Z"); // leap day
    }

    #[test]
    fn maintenance_actions() {
        let mut m = MemPlatform::new();
        save_config(&mut m).unwrap();
        assert!(m.log.iter().any(|l| l == "RUN config save -y"), "{:?}", m.log);

        set_next_image(&mut m, &ImageInput { image: "SONiC-OS-202405.2".into() }).unwrap();
        assert!(
            m.log.iter().any(|l| l == "RUN sonic-installer set-next-boot SONiC-OS-202405.2"),
            "{:?}",
            m.log
        );
        let err = set_next_image(&mut m, &ImageInput { image: "two words".into() }).unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));

        install_image(&mut m, &UrlInput { url: "https://img.example.com/sonic.bin".into() })
            .unwrap();
        assert!(
            m.log.iter().any(|l| l.contains("sonic-installer install -y https://img.example.com")),
            "{:?}",
            m.log
        );
        let err = install_image(&mut m, &UrlInput { url: "ftp://nope".into() }).unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));

        // A failing installer surfaces as 422 with its own message.
        let mut failing = MemPlatform::new();
        failing.on_cmd(
            &["sonic-installer", "set-next-boot"],
            CmdOutput { ok: false, stdout: String::new(), stderr: "Image does not exist".into() },
        );
        let err = set_next_image(&mut failing, &ImageInput { image: "SONiC-OS-nope".into() })
            .unwrap_err();
        match err {
            WriteError::Unprocessable(msg) => assert!(msg.contains("does not exist"), "{msg}"),
            other => panic!("expected Unprocessable, got {other:?}"),
        }
    }

    #[test]
    fn backup_and_restore() {
        let mut m = MemPlatform::new();
        let err = backup(&mut m).unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
        m.seed_file("/etc/sonic/config_db.json", "{\"DEVICE_METADATA\": {}}");
        assert_eq!(backup(&mut m).unwrap(), "{\"DEVICE_METADATA\": {}}");

        restore(
            &mut m,
            &RestoreInput {
                config: json!({ "DEVICE_METADATA": { "localhost": { "hostname": "leaf1" } } }),
            },
        )
        .unwrap();
        assert!(m.log.iter().any(|l| l == "WRITE-FILE /etc/sonic/config_db.json"), "{:?}", m.log);
        assert!(m.log.iter().any(|l| l == "RUN config reload -y"), "{:?}", m.log);
        assert!(m.files.get("/etc/sonic/config_db.json").unwrap().contains("leaf1"));

        // Implausible dumps are refused before anything is written.
        for config in [json!("nope"), json!({ "PORT": {} }), json!({ "DEVICE_METADATA": {}, "X": 5 })] {
            let err = restore(&mut m, &RestoreInput { config }).unwrap_err();
            assert!(
                matches!(err, WriteError::BadRequest(_) | WriteError::Unprocessable(_)),
                "{:?}",
                err
            );
        }
    }
}
