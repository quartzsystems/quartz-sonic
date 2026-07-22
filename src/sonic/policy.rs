//! Routing policy (prefix lists + route maps) for the console's Configure →
//! Routing → Policy page.
//!
//! Community SONiC has no CONFIG_DB schema for these, so — like the OSPF and
//! IS-IS panels — FRR is programmed directly through vtysh in the bgp
//! container and state is read back by parsing `show running-config`.
//! Support is gated on the bgp container being available (that's where vtysh
//! and the FRR daemons live).
//!
//! Writes are whole-object replaces: a PUT deletes the FRR prefix list /
//! route map and re-adds every rule inside one vtysh transaction, so the
//! live object always matches the console's full desired set. Deletes are
//! refused while something still references the object (a route map matching
//! a prefix list; BGP/OSPF applying a route map). Persistence follows the
//! routing-config-mode rules (`vtysh -c "write memory"` in split modes only).

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, Platform};
use super::switching::{WriteError, WriteResult};

const UNSUPPORTED: &str =
    "routing policy requires the bgp container (FRR/vtysh), which is not running on this image";

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

// ── running-config parsing (pure) ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PrefixRule {
    pub seq: u32,
    pub action: String,
    pub prefix: String,
    pub ge: Option<u32>,
    pub le: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PrefixList {
    pub name: String,
    pub family: String,
    pub rules: Vec<PrefixRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct MatchClauses {
    pub ip_prefix_list: Option<String>,
    pub ipv6_prefix_list: Option<String>,
    pub community: Option<String>,
    pub metric: Option<u64>,
    pub tag: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SetClauses {
    pub local_preference: Option<u64>,
    pub metric: Option<u64>,
    pub community: Option<String>,
    pub as_path_prepend: Option<String>,
    pub ip_next_hop: Option<String>,
    pub origin: Option<String>,
    pub tag: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RouteMapEntry {
    pub seq: u32,
    pub action: String,
    pub description: Option<String>,
    #[serde(rename = "match")]
    pub matches: MatchClauses,
    pub set: SetClauses,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RouteMap {
    pub name: String,
    pub entries: Vec<RouteMapEntry>,
}

#[derive(Debug, Default)]
pub struct PolicyRunning {
    pub prefix_lists: Vec<PrefixList>,
    pub route_maps: Vec<RouteMap>,
    /// route-map names referenced outside their own definitions (BGP
    /// neighbors, redistribute clauses, OSPF, …) — the delete guard.
    pub route_map_refs: Vec<String>,
}

impl PolicyRunning {
    pub fn prefix_list(&self, name: &str) -> Option<&PrefixList> {
        self.prefix_lists.iter().find(|l| l.name == name)
    }

    pub fn route_map(&self, name: &str) -> Option<&RouteMap> {
        self.route_maps.iter().find(|m| m.name == name)
    }
}

fn parse_num_token(tokens: &[&str], key: &str) -> Option<u64> {
    let i = tokens.iter().position(|t| *t == key)?;
    tokens.get(i + 1)?.parse().ok()
}

/// One `ip|ipv6 prefix-list NAME seq N ACTION PREFIX [ge X] [le Y]` line.
fn parse_prefix_line(family: &str, rest: &str, lists: &mut Vec<PrefixList>) {
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    // NAME seq N ACTION PREFIX …
    let [name, "seq", seq, action, prefix, ..] = tokens.as_slice() else { return };
    let Ok(seq) = seq.parse::<u32>() else { return };
    if *action != "permit" && *action != "deny" {
        return;
    }
    let prefix = match *prefix {
        "any" if family == "ipv4" => "0.0.0.0/0".to_string(),
        "any" => "::/0".to_string(),
        p => p.to_string(),
    };
    let rule = PrefixRule {
        seq,
        action: action.to_string(),
        prefix,
        ge: parse_num_token(&tokens, "ge").map(|n| n as u32),
        le: parse_num_token(&tokens, "le").map(|n| n as u32),
    };
    match lists.iter_mut().find(|l| l.name == *name && l.family == family) {
        Some(list) => list.rules.push(rule),
        None => lists.push(PrefixList {
            name: name.to_string(),
            family: family.to_string(),
            rules: vec![rule],
        }),
    }
}

/// Parse the policy-relevant parts of `show running-config`. Pure, tolerant.
pub fn parse_running_config(text: &str) -> PolicyRunning {
    let mut out = PolicyRunning::default();
    let mut entry: Option<(String, RouteMapEntry)> = None;

    let finish = |out: &mut PolicyRunning, entry: &mut Option<(String, RouteMapEntry)>| {
        let Some((name, e)) = entry.take() else { return };
        match out.route_maps.iter_mut().find(|m| m.name == name) {
            Some(map) => map.entries.push(e),
            None => out.route_maps.push(RouteMap { name, entries: vec![e] }),
        }
    };

    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("ip prefix-list ") {
            finish(&mut out, &mut entry);
            parse_prefix_line("ipv4", rest, &mut out.prefix_lists);
            continue;
        }
        if let Some(rest) = line.strip_prefix("ipv6 prefix-list ") {
            finish(&mut out, &mut entry);
            parse_prefix_line("ipv6", rest, &mut out.prefix_lists);
            continue;
        }
        if let Some(rest) = line.strip_prefix("route-map ") {
            finish(&mut out, &mut entry);
            let tokens: Vec<&str> = rest.split_whitespace().collect();
            if let [name, action @ ("permit" | "deny"), seq] = tokens.as_slice() {
                if let Ok(seq) = seq.parse() {
                    entry = Some((
                        name.to_string(),
                        RouteMapEntry {
                            seq,
                            action: action.to_string(),
                            description: None,
                            matches: MatchClauses::default(),
                            set: SetClauses::default(),
                        },
                    ));
                }
            }
            continue;
        }
        if line == "exit" || line == "!" || line == "end" {
            finish(&mut out, &mut entry);
            continue;
        }
        if let Some((_, e)) = entry.as_mut() {
            parse_entry_line(line, e);
            continue;
        }
        // Outside any route-map block: a line mentioning "route-map NAME"
        // is a reference (neighbor/redistribute/default-originate/…).
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = tokens.iter().position(|t| *t == "route-map") {
            if let Some(name) = tokens.get(i + 1) {
                out.route_map_refs.push(name.to_string());
            }
        }
    }
    finish(&mut out, &mut entry);
    out
}

fn parse_entry_line(line: &str, e: &mut RouteMapEntry) {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if let Some(desc) = line.strip_prefix("description ") {
        e.description = Some(desc.trim().to_string());
        return;
    }
    match tokens.as_slice() {
        ["match", "ip", "address", "prefix-list", name] => {
            e.matches.ip_prefix_list = Some(name.to_string());
        }
        ["match", "ipv6", "address", "prefix-list", name] => {
            e.matches.ipv6_prefix_list = Some(name.to_string());
        }
        ["match", "community", name, ..] => e.matches.community = Some(name.to_string()),
        ["match", "metric", n] => e.matches.metric = n.parse().ok(),
        ["match", "tag", n] => e.matches.tag = n.parse().ok(),
        ["set", "local-preference", n] => e.set.local_preference = n.parse().ok(),
        ["set", "metric", n] => e.set.metric = n.parse().ok(),
        ["set", "community", rest @ ..] if !rest.is_empty() => {
            e.set.community = Some(rest.join(" "));
        }
        ["set", "as-path", "prepend", rest @ ..] if !rest.is_empty() => {
            e.set.as_path_prepend = Some(rest.join(" "));
        }
        ["set", "ip", "next-hop", addr] => e.set.ip_next_hop = Some(addr.to_string()),
        ["set", "origin", o @ ("igp" | "egp" | "incomplete")] => {
            e.set.origin = Some(o.to_string());
        }
        ["set", "tag", n] => e.set.tag = n.parse().ok(),
        _ => {}
    }
}

// ── GET /api/routing/policy ─────────────────────────────────────────────────

fn running_config(plat: &mut dyn Platform) -> anyhow::Result<PolicyRunning> {
    let out = plat.run("vtysh", &["-c", "show running-config"])?;
    if !out.ok {
        anyhow::bail!("vtysh show running-config failed: {}", out.stderr.trim());
    }
    Ok(parse_running_config(&out.stdout))
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    if !probe::current(plat).bgp_available() {
        return Ok(json!({
            "capability": Capability::no(UNSUPPORTED),
            "prefix_lists": [], "route_maps": [],
        }));
    }
    let mut running = running_config(plat)?;
    running.prefix_lists.sort_by(|a, b| a.name.cmp(&b.name));
    for l in &mut running.prefix_lists {
        l.rules.sort_by_key(|r| r.seq);
    }
    running.route_maps.sort_by(|a, b| a.name.cmp(&b.name));
    for m in &mut running.route_maps {
        m.entries.sort_by_key(|e| e.seq);
    }
    Ok(json!({
        "capability": Capability::yes(),
        "prefix_lists": running.prefix_lists,
        "route_maps": running.route_maps,
    }))
}

// ── shared write plumbing ───────────────────────────────────────────────────

fn require_supported(plat: &mut dyn Platform) -> std::result::Result<probe::Probe, WriteError> {
    let p = probe::current(plat);
    if !p.bgp_available() {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    Ok(p)
}

/// Run one vtysh configuration batch, then persist per the routing-config
/// mode (same contract as the IS-IS module).
fn vtysh_config(plat: &mut dyn Platform, p: &probe::Probe, lines: &[String]) -> WriteResult {
    let mut args: Vec<&str> = Vec::with_capacity(lines.len() * 2 + 2);
    args.push("-c");
    args.push("configure terminal");
    for line in lines {
        args.push("-c");
        args.push(line);
    }
    let out = plat
        .run("vtysh", &args)
        .map_err(|e| WriteError::Internal(format!("vtysh: {e:#}")))?;
    if !out.ok {
        return Err(WriteError::Internal(format!(
            "vtysh configuration failed: {}",
            if out.stderr.trim().is_empty() { out.stdout.trim() } else { out.stderr.trim() }
        )));
    }
    if p.frr_write_memory_needed() {
        let out = plat
            .run("vtysh", &["-c", "write memory"])
            .map_err(|e| WriteError::Internal(format!("vtysh write memory: {e:#}")))?;
        if !out.ok {
            tracing::warn!("vtysh write memory failed: {}", out.stderr.trim());
        }
    }
    Ok(())
}

/// Object names travel into vtysh command lines — keep them to characters
/// that can't smuggle in another command or break tokenization.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// Free-text fields (descriptions, community strings) ride the same command
/// lines: printable ASCII only, no quotes.
fn check_text(what: &str, s: &str, max: usize) -> std::result::Result<(), String> {
    if s.is_empty() || s.len() > max {
        return Err(format!("invalid {what}: must be 1-{max} characters"));
    }
    if !s.bytes().all(|b| (0x20..0x7f).contains(&b) && b != b'"') {
        return Err(format!("invalid {what}: printable ASCII only"));
    }
    Ok(())
}

// ── prefix lists ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PrefixRuleInput {
    pub seq: u32,
    pub action: String,
    pub prefix: String,
    pub ge: Option<u32>,
    pub le: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct PrefixListInput {
    pub family: String,
    pub rules: Vec<PrefixRuleInput>,
}

fn check_action(action: &str) -> std::result::Result<(), String> {
    match action {
        "permit" | "deny" => Ok(()),
        other => Err(format!("invalid action {other:?} (permit or deny)")),
    }
}

fn check_prefix_rule(family: &str, r: &PrefixRuleInput) -> std::result::Result<(), String> {
    if r.seq == 0 {
        return Err("seq must be positive".to_string());
    }
    check_action(&r.action)?;
    let err = || format!("invalid {family} prefix {:?}", r.prefix);
    let (ip, len) = r.prefix.split_once('/').ok_or_else(err)?;
    let ip: std::net::IpAddr = ip.parse().map_err(|_| err())?;
    let len: u32 = len.parse().map_err(|_| err())?;
    let max = if family == "ipv4" { 32 } else { 128 };
    if len > max || ip.is_ipv4() != (family == "ipv4") {
        return Err(err());
    }
    for (name, v) in [("ge", r.ge), ("le", r.le)] {
        if let Some(v) = v {
            if v < len || v > max {
                return Err(format!("invalid {name} {v} (must be {len}-{max})"));
            }
        }
    }
    if let (Some(ge), Some(le)) = (r.ge, r.le) {
        if ge > le {
            return Err(format!("ge {ge} exceeds le {le}"));
        }
    }
    Ok(())
}

fn family_keyword(family: &str) -> std::result::Result<&'static str, String> {
    match family {
        "ipv4" => Ok("ip"),
        "ipv6" => Ok("ipv6"),
        other => Err(format!("invalid family {other:?} (ipv4 or ipv6)")),
    }
}

/// PUT /api/routing/policy/prefix-lists/{name} — atomically replace the FRR
/// object (delete + re-add inside one vtysh transaction).
pub fn put_prefix_list(plat: &mut dyn Platform, name: &str, input: &PrefixListInput) -> WriteResult {
    let _lock = store::feature_lock("policy");
    let p = require_supported(plat)?;
    if !valid_name(name) {
        return Err(bad(format!("invalid prefix list name {name:?}")));
    }
    let kw = family_keyword(&input.family).map_err(bad)?;
    if input.rules.is_empty() {
        return Err(bad("a prefix list needs at least one rule"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for r in &input.rules {
        check_prefix_rule(&input.family, r).map_err(bad)?;
        if !seen.insert(r.seq) {
            return Err(bad(format!("duplicate seq {}", r.seq)));
        }
    }
    let running = running_config(plat).map_err(|e| WriteError::Internal(format!("{e:#}")))?;
    let mut lines = Vec::new();
    // Remove the existing list first (whichever family it currently has —
    // a family change must not leave the old-family list behind).
    if let Some(cur) = running.prefix_list(name) {
        let cur_kw = if cur.family == "ipv4" { "ip" } else { "ipv6" };
        lines.push(format!("no {cur_kw} prefix-list {name}"));
    }
    for r in &input.rules {
        let mut line = format!("{kw} prefix-list {name} seq {} {} {}", r.seq, r.action, r.prefix);
        if let Some(ge) = r.ge {
            line.push_str(&format!(" ge {ge}"));
        }
        if let Some(le) = r.le {
            line.push_str(&format!(" le {le}"));
        }
        lines.push(line);
    }
    vtysh_config(plat, &p, &lines)
}

/// DELETE /api/routing/policy/prefix-lists/{name} — refused while a route
/// map still matches on it.
pub fn delete_prefix_list(plat: &mut dyn Platform, name: &str) -> WriteResult {
    let _lock = store::feature_lock("policy");
    let p = require_supported(plat)?;
    if !valid_name(name) {
        return Err(bad(format!("invalid prefix list name {name:?}")));
    }
    let running = running_config(plat).map_err(|e| WriteError::Internal(format!("{e:#}")))?;
    let Some(list) = running.prefix_list(name) else {
        return Err(WriteError::NotFound(format!("no such prefix list {name}")));
    };
    let users: Vec<&str> = running
        .route_maps
        .iter()
        .filter(|m| {
            m.entries.iter().any(|e| {
                e.matches.ip_prefix_list.as_deref() == Some(name)
                    || e.matches.ipv6_prefix_list.as_deref() == Some(name)
            })
        })
        .map(|m| m.name.as_str())
        .collect();
    if !users.is_empty() {
        return Err(WriteError::Conflict(format!(
            "prefix list {name} is still referenced by route map(s): {}",
            users.join(", ")
        )));
    }
    let kw = if list.family == "ipv4" { "ip" } else { "ipv6" };
    vtysh_config(plat, &p, &[format!("no {kw} prefix-list {name}")])
}

// ── route maps ──────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MatchInput {
    pub ip_prefix_list: Option<String>,
    pub ipv6_prefix_list: Option<String>,
    pub community: Option<String>,
    pub metric: Option<u64>,
    pub tag: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SetInput {
    pub local_preference: Option<u64>,
    pub metric: Option<u64>,
    pub community: Option<String>,
    pub as_path_prepend: Option<String>,
    pub ip_next_hop: Option<String>,
    pub origin: Option<String>,
    pub tag: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct RouteMapEntryInput {
    pub seq: u32,
    pub action: String,
    pub description: Option<String>,
    #[serde(default, rename = "match")]
    pub matches: MatchInput,
    #[serde(default)]
    pub set: SetInput,
}

#[derive(Debug, Deserialize)]
pub struct RouteMapInput {
    pub entries: Vec<RouteMapEntryInput>,
}

fn check_entry(e: &RouteMapEntryInput) -> std::result::Result<(), String> {
    if !(1..=65535).contains(&e.seq) {
        return Err(format!("invalid seq {} (must be 1-65535)", e.seq));
    }
    check_action(&e.action)?;
    if let Some(d) = &e.description {
        check_text("description", d, 100)?;
    }
    for (what, v) in [
        ("match.ip_prefix_list", &e.matches.ip_prefix_list),
        ("match.ipv6_prefix_list", &e.matches.ipv6_prefix_list),
        ("match.community", &e.matches.community),
    ] {
        if let Some(v) = v {
            if !valid_name(v) {
                return Err(format!("invalid {what} {v:?}"));
            }
        }
    }
    for (what, v) in [("set.community", &e.set.community), ("set.as_path_prepend", &e.set.as_path_prepend)]
    {
        if let Some(v) = v {
            check_text(what, v, 200)?;
        }
    }
    if let Some(prepend) = &e.set.as_path_prepend {
        if prepend.split_whitespace().any(|t| t.parse::<u32>().is_err()) {
            return Err(format!("invalid set.as_path_prepend {prepend:?} (space-separated ASNs)"));
        }
    }
    if let Some(nh) = &e.set.ip_next_hop {
        if nh.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("invalid set.ip_next_hop {nh:?}"));
        }
    }
    if let Some(o) = &e.set.origin {
        if !matches!(o.as_str(), "igp" | "egp" | "incomplete") {
            return Err(format!("invalid set.origin {o:?} (igp, egp, or incomplete)"));
        }
    }
    Ok(())
}

/// One route-map entry as its vtysh command lines.
fn entry_lines(name: &str, e: &RouteMapEntryInput, lines: &mut Vec<String>) {
    lines.push(format!("route-map {name} {} {}", e.action, e.seq));
    if let Some(d) = &e.description {
        lines.push(format!("description {d}"));
    }
    let m = &e.matches;
    if let Some(v) = &m.ip_prefix_list {
        lines.push(format!("match ip address prefix-list {v}"));
    }
    if let Some(v) = &m.ipv6_prefix_list {
        lines.push(format!("match ipv6 address prefix-list {v}"));
    }
    if let Some(v) = &m.community {
        lines.push(format!("match community {v}"));
    }
    if let Some(v) = m.metric {
        lines.push(format!("match metric {v}"));
    }
    if let Some(v) = m.tag {
        lines.push(format!("match tag {v}"));
    }
    let s = &e.set;
    if let Some(v) = s.local_preference {
        lines.push(format!("set local-preference {v}"));
    }
    if let Some(v) = s.metric {
        lines.push(format!("set metric {v}"));
    }
    if let Some(v) = &s.community {
        lines.push(format!("set community {v}"));
    }
    if let Some(v) = &s.as_path_prepend {
        lines.push(format!("set as-path prepend {v}"));
    }
    if let Some(v) = &s.ip_next_hop {
        lines.push(format!("set ip next-hop {v}"));
    }
    if let Some(v) = &s.origin {
        lines.push(format!("set origin {v}"));
    }
    if let Some(v) = s.tag {
        lines.push(format!("set tag {v}"));
    }
    lines.push("exit".to_string());
}

/// PUT /api/routing/policy/route-maps/{name} — the body's entries replace
/// the live set.
pub fn put_route_map(plat: &mut dyn Platform, name: &str, input: &RouteMapInput) -> WriteResult {
    let _lock = store::feature_lock("policy");
    let p = require_supported(plat)?;
    if !valid_name(name) {
        return Err(bad(format!("invalid route map name {name:?}")));
    }
    if input.entries.is_empty() {
        return Err(bad("a route map needs at least one entry"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for e in &input.entries {
        check_entry(e).map_err(bad)?;
        if !seen.insert(e.seq) {
            return Err(bad(format!("duplicate seq {}", e.seq)));
        }
    }
    let running = running_config(plat).map_err(|e| WriteError::Internal(format!("{e:#}")))?;
    let mut lines = Vec::new();
    if running.route_map(name).is_some() {
        lines.push(format!("no route-map {name}"));
    }
    for e in &input.entries {
        entry_lines(name, e, &mut lines);
    }
    vtysh_config(plat, &p, &lines)
}

/// DELETE /api/routing/policy/route-maps/{name} — refused while BGP/OSPF
/// still applies it.
pub fn delete_route_map(plat: &mut dyn Platform, name: &str) -> WriteResult {
    let _lock = store::feature_lock("policy");
    let p = require_supported(plat)?;
    if !valid_name(name) {
        return Err(bad(format!("invalid route map name {name:?}")));
    }
    let running = running_config(plat).map_err(|e| WriteError::Internal(format!("{e:#}")))?;
    if running.route_map(name).is_none() {
        return Err(WriteError::NotFound(format!("no such route map {name}")));
    }
    if running.route_map_refs.iter().any(|r| r == name) {
        return Err(WriteError::Conflict(format!(
            "route map {name} is still applied (BGP neighbor / redistribute / OSPF); detach it first"
        )));
    }
    vtysh_config(plat, &p, &[format!("no route-map {name}")])
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::store::mem::MemPlatform;
    use super::super::store::CmdOutput;
    use super::super::CONFIG_DB;
    use super::*;

    const RUNNING: &str = "\
frr version 8.5\n!\nrouter bgp 65100\n neighbor 10.0.0.1 remote-as 65200\n \
address-family ipv4 unicast\n  neighbor 10.0.0.1 route-map RM-UPSTREAM-IN in\n  \
redistribute connected route-map RM-CONN\n exit-address-family\nexit\n!\n\
ip prefix-list LAN-PREFIXES seq 5 permit 10.0.0.0/8 ge 16 le 24\n\
ip prefix-list LAN-PREFIXES seq 10 deny any\n\
ipv6 prefix-list V6-LAN seq 5 permit fd00::/8\n!\n\
route-map RM-UPSTREAM-IN permit 10\n description upstream in\n \
match ip address prefix-list LAN-PREFIXES\n set local-preference 200\n \
set community 65000:100 65000:200\nexit\n!\n\
route-map RM-UPSTREAM-IN deny 20\nexit\n!\n\
route-map RM-UNUSED permit 10\n set as-path prepend 65000 65000\n \
set origin igp\n set metric 50\nexit\n!\n";

    fn bgp_capable() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed(CONFIG_DB, "FEATURE|bgp", &[("state", "enabled")]);
        m.on_cmd(
            &["vtysh", "-c", "show running-config"],
            CmdOutput { ok: true, stdout: RUNNING.into(), stderr: String::new() },
        );
        m
    }

    #[test]
    fn parses_prefix_lists_and_route_maps() {
        let r = parse_running_config(RUNNING);
        let lan = r.prefix_list("LAN-PREFIXES").unwrap();
        assert_eq!(lan.family, "ipv4");
        assert_eq!(lan.rules.len(), 2);
        assert_eq!(lan.rules[0].seq, 5);
        assert_eq!(lan.rules[0].ge, Some(16));
        assert_eq!(lan.rules[0].le, Some(24));
        assert_eq!(lan.rules[1].action, "deny");
        assert_eq!(lan.rules[1].prefix, "0.0.0.0/0"); // "any"
        let v6 = r.prefix_list("V6-LAN").unwrap();
        assert_eq!(v6.family, "ipv6");
        assert_eq!(v6.rules[0].prefix, "fd00::/8");

        let rm = r.route_map("RM-UPSTREAM-IN").unwrap();
        assert_eq!(rm.entries.len(), 2);
        let e = &rm.entries[0];
        assert_eq!(e.seq, 10);
        assert_eq!(e.action, "permit");
        assert_eq!(e.description.as_deref(), Some("upstream in"));
        assert_eq!(e.matches.ip_prefix_list.as_deref(), Some("LAN-PREFIXES"));
        assert_eq!(e.set.local_preference, Some(200));
        assert_eq!(e.set.community.as_deref(), Some("65000:100 65000:200"));
        assert_eq!(rm.entries[1].action, "deny");
        let unused = r.route_map("RM-UNUSED").unwrap();
        assert_eq!(unused.entries[0].set.as_path_prepend.as_deref(), Some("65000 65000"));
        assert_eq!(unused.entries[0].set.origin.as_deref(), Some("igp"));

        // References: applied route maps, but never the definitions.
        assert!(r.route_map_refs.contains(&"RM-UPSTREAM-IN".to_string()));
        assert!(r.route_map_refs.contains(&"RM-CONN".to_string()));
        assert!(!r.route_map_refs.contains(&"RM-UNUSED".to_string()));
    }

    #[test]
    fn get_document_shape() {
        let mut m = bgp_capable();
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        assert_eq!(doc["prefix_lists"][0]["name"], "LAN-PREFIXES");
        let upstream = doc["route_maps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == "RM-UPSTREAM-IN")
            .unwrap();
        assert_eq!(upstream["entries"][0]["match"]["ip_prefix_list"], "LAN-PREFIXES");
        // Unsupported without the bgp container.
        let mut bare = MemPlatform::new();
        let doc = get(&mut bare).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        assert_eq!(doc["prefix_lists"], json!([]));
    }

    #[test]
    fn prefix_list_put_replaces_atomically() {
        let mut m = bgp_capable();
        put_prefix_list(
            &mut m,
            "LAN-PREFIXES",
            &PrefixListInput {
                family: "ipv4".into(),
                rules: vec![PrefixRuleInput {
                    seq: 5,
                    action: "permit".into(),
                    prefix: "10.0.0.0/8".into(),
                    ge: None,
                    le: Some(24),
                }],
            },
        )
        .unwrap();
        let cfg = m.log.iter().find(|l| l.contains("configure terminal")).unwrap();
        let no = cfg.find("no ip prefix-list LAN-PREFIXES").expect("delete first");
        let add = cfg.find("ip prefix-list LAN-PREFIXES seq 5 permit 10.0.0.0/8 le 24").unwrap();
        assert!(no < add, "{cfg}");
    }

    #[test]
    fn prefix_list_validation() {
        let mut m = bgp_capable();
        let rule = |prefix: &str, ge, le| PrefixRuleInput {
            seq: 5,
            action: "permit".into(),
            prefix: prefix.into(),
            ge,
            le,
        };
        for (family, r) in [
            ("ipv4", rule("10.0.0.0", None, None)),          // not a CIDR
            ("ipv4", rule("fd00::/8", None, None)),          // family mismatch
            ("ipv6", rule("10.0.0.0/8", None, None)),        // family mismatch
            ("ipv4", rule("10.0.0.0/8", Some(4), None)),     // ge < prefix len
            ("ipv4", rule("10.0.0.0/8", Some(24), Some(16))), // ge > le
            ("ipv4", rule("10.0.0.0/8", None, Some(33))),    // le > 32
            ("nope", rule("10.0.0.0/8", None, None)),        // bad family
        ] {
            let err = put_prefix_list(
                &mut m,
                "TEST",
                &PrefixListInput { family: family.into(), rules: vec![r] },
            )
            .unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{family}");
        }
        // Empty rules and bad names too.
        let err = put_prefix_list(
            &mut m,
            "TEST",
            &PrefixListInput { family: "ipv4".into(), rules: vec![] },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
        let err = put_prefix_list(
            &mut m,
            "bad name",
            &PrefixListInput { family: "ipv4".into(), rules: vec![rule("10.0.0.0/8", None, None)] },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
    }

    #[test]
    fn prefix_list_delete_guarded_by_references() {
        let mut m = bgp_capable();
        let err = delete_prefix_list(&mut m, "LAN-PREFIXES").unwrap_err();
        match err {
            WriteError::Conflict(msg) => assert!(msg.contains("RM-UPSTREAM-IN"), "{msg}"),
            other => panic!("expected Conflict, got {other:?}"),
        }
        // Unreferenced list deletes with the right family keyword.
        delete_prefix_list(&mut m, "V6-LAN").unwrap();
        let cfg = m.log.iter().find(|l| l.contains("no ipv6 prefix-list V6-LAN")).unwrap();
        assert!(cfg.contains("configure terminal"), "{cfg}");
        // Unknown → 404.
        let err = delete_prefix_list(&mut m, "NOPE").unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
    }

    #[test]
    fn route_map_put_emits_full_entries() {
        let mut m = bgp_capable();
        put_route_map(
            &mut m,
            "RM-UNUSED",
            &RouteMapInput {
                entries: vec![RouteMapEntryInput {
                    seq: 10,
                    action: "permit".into(),
                    description: Some("via upstream".into()),
                    matches: MatchInput {
                        ip_prefix_list: Some("LAN-PREFIXES".into()),
                        metric: Some(100),
                        ..Default::default()
                    },
                    set: SetInput {
                        local_preference: Some(300),
                        as_path_prepend: Some("65000 65000".into()),
                        origin: Some("igp".into()),
                        ..Default::default()
                    },
                }],
            },
        )
        .unwrap();
        let cfg = m.log.iter().find(|l| l.contains("configure terminal")).unwrap();
        assert!(cfg.contains("no route-map RM-UNUSED"), "{cfg}");
        assert!(cfg.contains("route-map RM-UNUSED permit 10"), "{cfg}");
        assert!(cfg.contains("description via upstream"), "{cfg}");
        assert!(cfg.contains("match ip address prefix-list LAN-PREFIXES"), "{cfg}");
        assert!(cfg.contains("match metric 100"), "{cfg}");
        assert!(cfg.contains("set local-preference 300"), "{cfg}");
        assert!(cfg.contains("set as-path prepend 65000 65000"), "{cfg}");
        assert!(cfg.contains("set origin igp"), "{cfg}");
    }

    #[test]
    fn route_map_validation_and_delete_guard() {
        let mut m = bgp_capable();
        let entry = |seq, action: &str| RouteMapEntryInput {
            seq,
            action: action.into(),
            description: None,
            matches: MatchInput::default(),
            set: SetInput::default(),
        };
        for input in [
            RouteMapInput { entries: vec![] },
            RouteMapInput { entries: vec![entry(0, "permit")] },
            RouteMapInput { entries: vec![entry(10, "allow")] },
            RouteMapInput { entries: vec![entry(10, "permit"), entry(10, "deny")] },
        ] {
            let err = put_route_map(&mut m, "RM-X", &input).unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)));
        }
        // Bad set values.
        let mut e = entry(10, "permit");
        e.set.ip_next_hop = Some("not-an-ip".into());
        let err = put_route_map(&mut m, "RM-X", &RouteMapInput { entries: vec![e] }).unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));
        let mut e = entry(10, "permit");
        e.set.as_path_prepend = Some("65000 nope".into());
        let err = put_route_map(&mut m, "RM-X", &RouteMapInput { entries: vec![e] }).unwrap_err();
        assert!(matches!(err, WriteError::BadRequest(_)));

        // Applied map can't be deleted; unused one can.
        let err = delete_route_map(&mut m, "RM-UPSTREAM-IN").unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
        delete_route_map(&mut m, "RM-UNUSED").unwrap();
        assert!(m.log.iter().any(|l| l.contains("no route-map RM-UNUSED")), "{:?}", m.log);
        let err = delete_route_map(&mut m, "RM-NOPE").unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
    }
}
