//! BFD for the console's Configure → Routing → BFD page.
//!
//! Community SONiC has no CONFIG_DB schema for BFD, so — like the routing
//! policy panels — FRR's bfdd is programmed directly through vtysh and read
//! back by parsing `show running-config`. Peer identity is (peer, interface,
//! vrf, multihop); a PUT replaces the whole FRR peer block inside one vtysh
//! transaction, and deletes travel POST-with-body because peer addresses
//! aren't path-safe. Live sessions come from `show bfd peers json`, which
//! includes sessions raised dynamically by BGP/OSPF (`neighbor … bfd`), not
//! just the configured peers. Persistence follows the routing-config-mode
//! rules (`vtysh -c "write memory"` in split modes only).

use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::policy::valid_name;
use super::probe::{self, Capability};
use super::store::{self, Platform};
use super::switching::{WriteError, WriteResult};

const UNSUPPORTED: &str =
    "BFD requires FRR's bfdd in the bgp container, which is not available on this image";

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

// ── running-config parsing (pure) ───────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Peer {
    pub peer: String,
    pub interface: Option<String>,
    pub local_address: Option<String>,
    pub multihop: bool,
    pub vrf: Option<String>,
    pub rx_interval_ms: Option<u64>,
    pub tx_interval_ms: Option<u64>,
    pub multiplier: Option<u64>,
    pub passive: bool,
    pub shutdown: bool,
}

/// Parse the `bfd` block of `show running-config`. Pure, tolerant; profile
/// sub-blocks are skipped.
pub fn parse_running_bfd(text: &str) -> Vec<Peer> {
    let mut peers = Vec::new();
    let mut in_bfd = false;
    let mut in_profile = false;
    let mut current: Option<Peer> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if !in_bfd {
            if line == "bfd" {
                in_bfd = true;
            }
            continue;
        }
        if in_profile {
            if line == "exit" || line == "!" {
                in_profile = false;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("peer ") {
            if let Some(p) = current.take() {
                peers.push(p);
            }
            current = parse_peer_line(rest);
            continue;
        }
        if line.starts_with("profile ") {
            if let Some(p) = current.take() {
                peers.push(p);
            }
            in_profile = true;
            continue;
        }
        if line == "exit" || line == "!" || line == "end" {
            match current.take() {
                Some(p) => peers.push(p), // closes the peer block
                // A bare "exit" with no open peer closes the bfd block
                // itself; "!" is just a separator.
                None => {
                    if line != "!" {
                        break;
                    }
                }
            }
            continue;
        }
        if let Some(p) = current.as_mut() {
            parse_setting_line(line, p);
        }
    }
    if let Some(p) = current.take() {
        peers.push(p);
    }
    peers
}

fn parse_peer_line(rest: &str) -> Option<Peer> {
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    let mut p = Peer { peer: tokens.first()?.to_string(), ..Default::default() };
    let mut i = 1;
    while i < tokens.len() {
        match tokens[i] {
            "multihop" => {
                p.multihop = true;
                i += 1;
            }
            "local-address" => {
                p.local_address = tokens.get(i + 1).map(|s| s.to_string());
                i += 2;
            }
            "interface" => {
                p.interface = tokens.get(i + 1).map(|s| s.to_string());
                i += 2;
            }
            "vrf" => {
                p.vrf = tokens.get(i + 1).map(|s| s.to_string());
                i += 2;
            }
            _ => i += 1,
        }
    }
    Some(p)
}

fn parse_setting_line(line: &str, p: &mut Peer) {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    match tokens.as_slice() {
        ["detect-multiplier", n] => p.multiplier = n.parse().ok(),
        ["receive-interval", n] => p.rx_interval_ms = n.parse().ok(),
        ["transmit-interval", n] => p.tx_interval_ms = n.parse().ok(),
        ["passive-mode"] => p.passive = true,
        ["no", "passive-mode"] => p.passive = false,
        ["shutdown"] => p.shutdown = true,
        ["no", "shutdown"] => p.shutdown = false,
        _ => {}
    }
}

// ── shared plumbing ─────────────────────────────────────────────────────────

fn require_supported(plat: &mut dyn Platform) -> std::result::Result<probe::Probe, WriteError> {
    let p = probe::current(plat);
    if !p.bfd_supported() {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    Ok(p)
}

fn configured_peers(plat: &mut dyn Platform) -> anyhow::Result<Vec<Peer>> {
    let out = plat.run("vtysh", &["-c", "show running-config"])?;
    if !out.ok {
        anyhow::bail!("vtysh show running-config failed: {}", out.stderr.trim());
    }
    Ok(parse_running_bfd(&out.stdout))
}

/// Run one vtysh configuration batch, then persist per the routing-config
/// mode (same contract as the policy/IS-IS modules).
fn vtysh_config(plat: &mut dyn Platform, p: &probe::Probe, lines: &[String]) -> WriteResult {
    let mut args: Vec<&str> = Vec::with_capacity(lines.len() * 2 + 2);
    args.push("-c");
    args.push("configure terminal");
    for line in lines {
        args.push("-c");
        args.push(line);
    }
    let out =
        plat.run("vtysh", &args).map_err(|e| WriteError::Internal(format!("vtysh: {e:#}")))?;
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

/// The FRR `peer …` identity line for a session.
fn identity_of(
    peer: &str,
    multihop: bool,
    local_address: Option<&str>,
    interface: Option<&str>,
    vrf: Option<&str>,
) -> String {
    let mut s = format!("peer {peer}");
    if multihop {
        s.push_str(" multihop");
    }
    if let Some(l) = local_address {
        s.push_str(&format!(" local-address {l}"));
    }
    if let Some(i) = interface {
        s.push_str(&format!(" interface {i}"));
    }
    if let Some(v) = vrf {
        s.push_str(&format!(" vrf {v}"));
    }
    s
}

/// Does a configured peer match the contract identity (peer, interface, vrf,
/// multihop)? Addresses compare parsed, so "FD00::1" matches "fd00::1".
fn same_identity(
    c: &Peer,
    peer: &IpAddr,
    interface: Option<&str>,
    vrf: Option<&str>,
    multihop: bool,
) -> bool {
    c.peer.parse::<IpAddr>().ok().as_ref() == Some(peer)
        && c.interface.as_deref() == interface
        && c.vrf.as_deref() == vrf
        && c.multihop == multihop
}

/// Interface names ride vtysh command lines — keep them to characters that
/// can't smuggle in another command.
fn valid_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

// ── GET /api/routing/bfd ────────────────────────────────────────────────────

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    if !probe::current(plat).bfd_supported() {
        return Ok(json!({ "capability": Capability::no(UNSUPPORTED), "peers": [] }));
    }
    let mut peers = configured_peers(plat)?;
    peers.sort_by(|a, b| {
        a.peer
            .cmp(&b.peer)
            .then_with(|| a.vrf.cmp(&b.vrf))
            .then_with(|| a.interface.cmp(&b.interface))
    });
    Ok(json!({ "capability": Capability::yes(), "peers": peers }))
}

// ── PUT /api/routing/bfd/peers ──────────────────────────────────────────────

/// The whole desired peer — an upsert replaces the FRR peer block for its
/// identity.
#[derive(Debug, Deserialize)]
pub struct PeerInput {
    pub peer: String,
    pub interface: Option<String>,
    pub local_address: Option<String>,
    pub multihop: bool,
    pub vrf: Option<String>,
    pub rx_interval_ms: Option<u32>,
    pub tx_interval_ms: Option<u32>,
    pub multiplier: Option<u32>,
    #[serde(default)]
    pub passive: bool,
    #[serde(default)]
    pub shutdown: bool,
}

pub fn put_peer(plat: &mut dyn Platform, input: &PeerInput) -> WriteResult {
    let _lock = store::feature_lock("bfd");
    let peer: IpAddr = input
        .peer
        .parse()
        .map_err(|_| bad(format!("invalid peer address {:?}", input.peer)))?;
    if let Some(l) = &input.local_address {
        let addr: IpAddr =
            l.parse().map_err(|_| bad(format!("invalid local_address {l:?}")))?;
        if addr.is_ipv4() != peer.is_ipv4() {
            return Err(bad("local_address and peer must be the same address family"));
        }
    }
    if input.multihop {
        if input.local_address.is_none() {
            return Err(bad("a multihop peer requires local_address"));
        }
        if input.interface.is_some() {
            return Err(bad("a multihop peer does not bind to an interface"));
        }
    }
    if let Some(i) = &input.interface {
        if !valid_iface(i) {
            return Err(bad(format!("invalid interface {i:?}")));
        }
    }
    if let Some(v) = &input.vrf {
        if !valid_name(v) {
            return Err(bad(format!("invalid vrf {v:?}")));
        }
    }
    for (what, v) in
        [("rx_interval_ms", input.rx_interval_ms), ("tx_interval_ms", input.tx_interval_ms)]
    {
        if let Some(v) = v {
            if !(10..=60000).contains(&v) {
                return Err(bad(format!("invalid {what} {v} (must be 10-60000)")));
            }
        }
    }
    if let Some(mult) = input.multiplier {
        if !(2..=255).contains(&mult) {
            return Err(bad(format!("invalid multiplier {mult} (must be 2-255)")));
        }
    }

    let p = require_supported(plat)?;
    let existing = configured_peers(plat).map_err(|e| WriteError::Internal(format!("{e:#}")))?;
    let mut lines = vec!["bfd".to_string()];
    // Atomic replace: delete the current block for this identity (with
    // whatever local-address it carries) and re-add in the same transaction.
    if let Some(cur) = existing.iter().find(|c| {
        same_identity(c, &peer, input.interface.as_deref(), input.vrf.as_deref(), input.multihop)
    }) {
        lines.push(format!(
            "no {}",
            identity_of(
                &cur.peer,
                cur.multihop,
                cur.local_address.as_deref(),
                cur.interface.as_deref(),
                cur.vrf.as_deref(),
            )
        ));
    }
    lines.push(identity_of(
        &input.peer,
        input.multihop,
        input.local_address.as_deref(),
        input.interface.as_deref(),
        input.vrf.as_deref(),
    ));
    if let Some(v) = input.rx_interval_ms {
        lines.push(format!("receive-interval {v}"));
    }
    if let Some(v) = input.tx_interval_ms {
        lines.push(format!("transmit-interval {v}"));
    }
    if let Some(v) = input.multiplier {
        lines.push(format!("detect-multiplier {v}"));
    }
    if input.passive {
        lines.push("passive-mode".to_string());
    }
    lines.push(if input.shutdown { "shutdown" } else { "no shutdown" }.to_string());
    lines.push("exit".to_string());
    lines.push("exit".to_string());
    vtysh_config(plat, &p, &lines)
}

// ── POST /api/routing/bfd/peers/delete ──────────────────────────────────────

/// The identity to delete — POST-with-body because peer addresses aren't
/// path-safe (same pattern as static routes).
#[derive(Debug, Deserialize)]
pub struct PeerKey {
    pub peer: String,
    pub interface: Option<String>,
    pub vrf: Option<String>,
    #[serde(default)]
    pub multihop: bool,
}

pub fn delete_peer(plat: &mut dyn Platform, key: &PeerKey) -> WriteResult {
    let _lock = store::feature_lock("bfd");
    let peer: IpAddr =
        key.peer.parse().map_err(|_| bad(format!("invalid peer address {:?}", key.peer)))?;
    let p = require_supported(plat)?;
    let existing = configured_peers(plat).map_err(|e| WriteError::Internal(format!("{e:#}")))?;
    let Some(cur) = existing.iter().find(|c| {
        same_identity(c, &peer, key.interface.as_deref(), key.vrf.as_deref(), key.multihop)
    }) else {
        return Err(WriteError::NotFound(format!("no configured BFD peer {}", key.peer)));
    };
    let lines = vec![
        "bfd".to_string(),
        format!(
            "no {}",
            identity_of(
                &cur.peer,
                cur.multihop,
                cur.local_address.as_deref(),
                cur.interface.as_deref(),
                cur.vrf.as_deref(),
            )
        ),
        "exit".to_string(),
    ];
    vtysh_config(plat, &p, &lines)
}

// ── GET /api/routing/bfd/sessions ───────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Session {
    pub peer: String,
    pub local_address: Option<String>,
    pub interface: Option<String>,
    pub vrf: Option<String>,
    pub multihop: bool,
    pub state: &'static str,
    pub remote_state: Option<&'static str>,
    pub uptime_seconds: Option<u64>,
    pub rx_interval_ms: Option<u64>,
    pub tx_interval_ms: Option<u64>,
    pub multiplier: Option<u64>,
    pub diagnostic: Option<String>,
    pub clients: Vec<&'static str>,
}

/// bfdd's state word onto the contract's enum. Pure, tolerant.
pub fn map_session_state(v: &str) -> &'static str {
    match v.to_ascii_lowercase().as_str() {
        "up" => "up",
        "init" => "init",
        "adm-down" | "admin-down" | "shutdown" => "admin_down",
        _ => "down",
    }
}

/// Peer addresses BGP runs BFD against (`neighbor … bfd` lines). Pure.
pub fn bgp_bfd_neighbors(text: &str) -> HashSet<String> {
    text.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.trim().split_whitespace().collect();
            match t.as_slice() {
                ["neighbor", addr, "bfd", ..] => Some(addr.to_string()),
                _ => None,
            }
        })
        .collect()
}

/// `show bfd peers json` into session documents. Pure, tolerant.
pub fn parse_sessions(json_text: &str, bgp_peers: &HashSet<String>) -> Vec<Session> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json_text) else { return Vec::new() };
    let Some(arr) = v.as_array() else { return Vec::new() };
    let mut out: Vec<Session> = arr
        .iter()
        .filter_map(|s| {
            let peer = s["peer"].as_str()?.to_string();
            let opt_str =
                |k: &str| s[k].as_str().filter(|v| !v.is_empty()).map(str::to_string);
            let diagnostic = s["diagnostic"]
                .as_str()
                .filter(|d| !d.is_empty() && !d.eq_ignore_ascii_case("ok"))
                .map(str::to_string);
            let clients = if bgp_peers.contains(&peer) { vec!["bgp"] } else { vec![] };
            Some(Session {
                local_address: opt_str("local"),
                interface: opt_str("interface"),
                vrf: opt_str("vrf").filter(|v| v != "default"),
                multihop: s["multihop"].as_bool().unwrap_or(false),
                state: map_session_state(s["status"].as_str().unwrap_or("")),
                remote_state: s["remote-status"].as_str().map(map_session_state),
                uptime_seconds: s["uptime"].as_u64(),
                rx_interval_ms: s["receive-interval"].as_u64(),
                tx_interval_ms: s["transmit-interval"].as_u64(),
                multiplier: s["detect-multiplier"].as_u64(),
                diagnostic,
                clients,
                peer,
            })
        })
        .collect();
    out.sort_by(|a, b| a.peer.cmp(&b.peer).then_with(|| a.vrf.cmp(&b.vrf)));
    out
}

pub fn get_sessions(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    if !probe::current(plat).bfd_supported() {
        return Ok(json!({ "capability": Capability::no(UNSUPPORTED), "sessions": [] }));
    }
    let out = plat.run("vtysh", &["-c", "show bfd peers json"])?;
    if !out.ok {
        anyhow::bail!("vtysh show bfd peers failed: {}", out.stderr.trim());
    }
    // `neighbor … bfd` lines say which sessions BGP raised; degrade to none.
    let running = plat
        .run("vtysh", &["-c", "show running-config"])
        .ok()
        .filter(|o| o.ok)
        .map(|o| o.stdout)
        .unwrap_or_default();
    let sessions = parse_sessions(&out.stdout, &bgp_bfd_neighbors(&running));
    Ok(json!({ "capability": Capability::yes(), "sessions": sessions }))
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::super::store::CmdOutput;
    use super::super::CONFIG_DB;
    use super::*;

    const RUNNING: &str = "\
frr version 8.5\n!\nbfd\n profile fast\n  receive-interval 100\n exit\n !\n \
peer 10.0.0.1 interface Ethernet0\n  detect-multiplier 5\n  receive-interval 200\n  \
transmit-interval 200\n exit\n !\n \
peer 10.9.9.9 multihop local-address 10.0.0.2 vrf VrfX\n  shutdown\n  passive-mode\n exit\n !\n\
exit\n!\nrouter bgp 65100\n neighbor 10.0.0.1 remote-as 65200\n neighbor 10.0.0.1 bfd\nexit\n";

    fn platform() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed(CONFIG_DB, "FEATURE|bgp", &[("state", "enabled")]);
        m.on_cmd(
            &["vtysh", "-c", "show daemons"],
            CmdOutput { ok: true, stdout: "zebra bgpd staticd bfdd\n".into(), stderr: String::new() },
        );
        m.on_cmd(
            &["vtysh", "-c", "show running-config"],
            CmdOutput { ok: true, stdout: RUNNING.into(), stderr: String::new() },
        );
        m
    }

    fn peer_input() -> PeerInput {
        PeerInput {
            peer: "10.0.0.1".into(),
            interface: Some("Ethernet0".into()),
            local_address: None,
            multihop: false,
            vrf: None,
            rx_interval_ms: Some(300),
            tx_interval_ms: Some(300),
            multiplier: Some(3),
            passive: false,
            shutdown: false,
        }
    }

    #[test]
    fn parses_running_config_peers() {
        let peers = parse_running_bfd(RUNNING);
        assert_eq!(peers.len(), 2); // the profile block is not a peer
        assert_eq!(peers[0].peer, "10.0.0.1");
        assert_eq!(peers[0].interface.as_deref(), Some("Ethernet0"));
        assert!(!peers[0].multihop);
        assert_eq!(peers[0].multiplier, Some(5));
        assert_eq!(peers[0].rx_interval_ms, Some(200));
        assert!(!peers[0].shutdown);
        assert_eq!(peers[1].peer, "10.9.9.9");
        assert!(peers[1].multihop);
        assert_eq!(peers[1].local_address.as_deref(), Some("10.0.0.2"));
        assert_eq!(peers[1].vrf.as_deref(), Some("VrfX"));
        assert!(peers[1].shutdown);
        assert!(peers[1].passive);
    }

    #[test]
    fn get_document_shape() {
        let mut m = platform();
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        let peers = doc["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0]["peer"], "10.0.0.1");
        assert_eq!(peers[0]["vrf"], serde_json::Value::Null);
        assert_eq!(peers[1]["local_address"], "10.0.0.2");
        // No bfdd → unsupported, empty document.
        let mut bare = MemPlatform::new();
        bare.seed(CONFIG_DB, "FEATURE|bgp", &[("state", "enabled")]);
        let doc = get(&mut bare).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        assert_eq!(doc["peers"], json!([]));
    }

    #[test]
    fn put_replaces_existing_identity_atomically() {
        let mut m = platform();
        put_peer(&mut m, &peer_input()).unwrap();
        let cfg = m.log.iter().find(|l| l.contains("configure terminal")).unwrap();
        let no = cfg.find("no peer 10.0.0.1 interface Ethernet0").expect("delete first");
        let add = cfg.rfind("peer 10.0.0.1 interface Ethernet0").unwrap();
        assert!(no < add, "{cfg}");
        assert!(cfg.contains("receive-interval 300"), "{cfg}");
        assert!(cfg.contains("no shutdown"), "{cfg}");
    }

    #[test]
    fn put_new_peer_skips_the_delete() {
        let mut m = platform();
        let mut input = peer_input();
        input.peer = "10.0.0.99".into();
        input.interface = None;
        input.shutdown = true;
        put_peer(&mut m, &input).unwrap();
        let cfg = m.log.iter().find(|l| l.contains("configure terminal")).unwrap();
        assert!(!cfg.contains("no peer"), "{cfg}");
        assert!(cfg.contains("-c peer 10.0.0.99 -c"), "{cfg}");
        assert!(cfg.contains("-c shutdown"), "{cfg}");
    }

    #[test]
    fn put_validation() {
        let mut m = platform();
        let mut bad_peer = peer_input();
        bad_peer.peer = "not-an-ip".into();
        let mut multihop_no_local = peer_input();
        multihop_no_local.multihop = true;
        multihop_no_local.interface = None;
        let mut multihop_iface = peer_input();
        multihop_iface.multihop = true;
        multihop_iface.local_address = Some("10.0.0.2".into());
        let mut family_mismatch = peer_input();
        family_mismatch.local_address = Some("fd00::1".into());
        let mut bad_rx = peer_input();
        bad_rx.rx_interval_ms = Some(5);
        let mut bad_mult = peer_input();
        bad_mult.multiplier = Some(1);
        let mut bad_iface = peer_input();
        bad_iface.interface = Some("eth0; reboot".into());
        for i in
            [bad_peer, multihop_no_local, multihop_iface, family_mismatch, bad_rx, bad_mult, bad_iface]
        {
            let err = put_peer(&mut m, &i).unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{err:?}");
        }
        // Unsupported image → 409 even for a valid payload.
        let mut bare = MemPlatform::new();
        let err = put_peer(&mut bare, &peer_input()).unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
    }

    #[test]
    fn delete_uses_the_configured_local_address() {
        let mut m = platform();
        delete_peer(
            &mut m,
            &PeerKey {
                peer: "10.9.9.9".into(),
                interface: None,
                vrf: Some("VrfX".into()),
                multihop: true,
            },
        )
        .unwrap();
        let cfg = m.log.iter().find(|l| l.contains("configure terminal")).unwrap();
        assert!(
            cfg.contains("no peer 10.9.9.9 multihop local-address 10.0.0.2 vrf VrfX"),
            "{cfg}"
        );
        // Unknown identity → 404 (10.9.9.9 without the vrf doesn't match).
        let err = delete_peer(
            &mut m,
            &PeerKey { peer: "10.9.9.9".into(), interface: None, vrf: None, multihop: true },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
    }

    #[test]
    fn sessions_include_dynamic_ones() {
        let mut m = platform();
        m.on_cmd(
            &["vtysh", "-c", "show bfd peers json"],
            CmdOutput {
                ok: true,
                stdout: r#"[
                  {"multihop":false,"peer":"10.0.0.1","local":"10.0.0.2","vrf":"default",
                   "interface":"Ethernet0","status":"up","uptime":73,"diagnostic":"ok",
                   "receive-interval":200,"transmit-interval":200,"detect-multiplier":5},
                  {"multihop":true,"peer":"10.9.9.9","local":"10.0.0.2","vrf":"VrfX",
                   "status":"shutdown","diagnostic":"control detection time expired"}
                ]"#
                .into(),
                stderr: String::new(),
            },
        );
        let doc = get_sessions(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        let sessions = doc["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0]["peer"], "10.0.0.1");
        assert_eq!(sessions[0]["vrf"], serde_json::Value::Null); // "default" → null
        assert_eq!(sessions[0]["state"], "up");
        assert_eq!(sessions[0]["uptime_seconds"], 73);
        assert_eq!(sessions[0]["rx_interval_ms"], 200);
        assert_eq!(sessions[0]["diagnostic"], serde_json::Value::Null); // "ok" → null
        assert_eq!(sessions[0]["clients"], json!(["bgp"])); // neighbor 10.0.0.1 bfd
        assert_eq!(sessions[1]["state"], "admin_down");
        assert_eq!(sessions[1]["vrf"], "VrfX");
        assert_eq!(sessions[1]["uptime_seconds"], serde_json::Value::Null);
        assert_eq!(sessions[1]["diagnostic"], "control detection time expired");
        assert_eq!(sessions[1]["clients"], json!([]));
    }
}
