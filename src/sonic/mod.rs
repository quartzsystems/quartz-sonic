//! SONiC platform access: the redis databases (CONFIG_DB / STATE_DB /
//! COUNTERS_DB, swsssdk-style) and system facts.
//!
//! All redis access is via the sync client and runs inside spawn_blocking
//! callers. Every reader degrades gracefully: a missing database, key, or
//! field yields a default value, never an error that would take down a
//! telemetry snapshot or the control stream.

use std::collections::HashMap;

use anyhow::{Context, Result};

use crate::proto::device::PolicyStat;

pub mod mgmtapi;
pub mod stats;
pub mod switching;
pub mod telemetry;

/// SONiC database ids (matching /var/run/redis/sonic-db/database_config.json).
pub const APPL_DB: i64 = 0;
pub const COUNTERS_DB: i64 = 2;
pub const CONFIG_DB: i64 = 4;
pub const STATE_DB: i64 = 6;

/// The redis unix socket every SONiC image ships; TCP localhost is the
/// fallback (some Enterprise builds bind TCP only).
#[cfg(unix)]
const REDIS_SOCK: &str = "/var/run/redis/redis.sock";
const REDIS_TCP: (&str, u16) = ("127.0.0.1", 6379);

fn connection(db: i64) -> Result<redis::Connection> {
    let redis_info = redis::RedisConnectionInfo { db, ..Default::default() };
    #[cfg(unix)]
    {
        if std::path::Path::new(REDIS_SOCK).exists() {
            let info = redis::ConnectionInfo {
                addr: redis::ConnectionAddr::Unix(REDIS_SOCK.into()),
                redis: redis_info.clone(),
            };
            if let Ok(conn) = redis::Client::open(info).and_then(|c| c.get_connection()) {
                return Ok(conn);
            }
        }
    }
    let info = redis::ConnectionInfo {
        addr: redis::ConnectionAddr::Tcp(REDIS_TCP.0.to_string(), REDIS_TCP.1),
        redis: redis_info,
    };
    redis::Client::open(info)
        .context("open redis client")?
        .get_connection()
        .context("connect to the SONiC redis instance")
}

fn hgetall(db: i64, key: &str) -> Result<HashMap<String, String>> {
    let mut conn = connection(db)?;
    redis::cmd("HGETALL")
        .arg(key)
        .query(&mut conn)
        .with_context(|| format!("HGETALL {key} (db {db})"))
}

/// HGETALL on an already-open connection; a missing key or a read error
/// degrades to an empty hash (bulk readers must not fail per-row).
fn hgetall_on(conn: &mut redis::Connection, key: &str) -> HashMap<String, String> {
    redis::cmd("HGETALL").arg(key).query(conn).unwrap_or_default()
}

/// Every key matching a redis glob `pattern`, collected with cursor SCAN —
/// never KEYS, which would block the instance all the SONiC daemons share.
fn scan_keys(conn: &mut redis::Connection, pattern: &str) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    let mut cursor: u64 = 0;
    loop {
        let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(200)
            .query(conn)
            .with_context(|| format!("SCAN {pattern}"))?;
        keys.extend(batch);
        cursor = next;
        if cursor == 0 {
            return Ok(keys);
        }
    }
}

/// Whether the SONiC redis instance answers a PING (health probe).
pub fn redis_ok() -> bool {
    connection(CONFIG_DB)
        .and_then(|mut c| redis::cmd("PING").query::<String>(&mut c).context("PING"))
        .map(|pong| pong == "PONG")
        .unwrap_or(false)
}

// ── system facts ──────────────────────────────────────────────────────────────

/// Facts for `/api/system/info`, all best-effort ("" when undetermined).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SystemFacts {
    pub hostname: String,
    pub sonic_version: String,
    pub platform: String,
    pub hwsku: String,
    pub serial: String,
}

pub fn system_facts() -> SystemFacts {
    let meta = hgetall(CONFIG_DB, "DEVICE_METADATA|localhost").unwrap_or_default();
    let get = |k: &str| meta.get(k).cloned().unwrap_or_default();
    SystemFacts {
        hostname: {
            let h = get("hostname");
            if h.is_empty() { read_hostname() } else { h }
        },
        sonic_version: sonic_version().unwrap_or_default(),
        platform: {
            let p = get("platform");
            if p.is_empty() { onie_platform().unwrap_or_default() } else { p }
        },
        hwsku: get("hwsku"),
        serial: serial_number().unwrap_or_default(),
    }
}

/// The system hostname (DeviceHello / info fallback).
pub fn read_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("COMPUTERNAME").ok()) // dev hosts
        .unwrap_or_else(|| "unknown".to_string())
}

/// `build_version` from /etc/sonic/sonic_version.yml.
fn sonic_version() -> Option<String> {
    parse_sonic_version(&std::fs::read_to_string("/etc/sonic/sonic_version.yml").ok()?)
}

/// Minimal line-based parse of sonic_version.yml — the file is flat
/// `key: 'value'` YAML; a full YAML parser is not worth the dependency.
pub fn parse_sonic_version(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let rest = l.strip_prefix("build_version:")?.trim();
        let v = rest.trim_matches(|c| c == '\'' || c == '"').trim();
        (!v.is_empty()).then(|| v.to_string())
    })
}

/// `onie_platform` from /host/machine.conf (pre-CONFIG_DB fallback).
fn onie_platform() -> Option<String> {
    let text = std::fs::read_to_string("/host/machine.conf").ok()?;
    text.lines().find_map(|l| {
        let rest = l.strip_prefix("onie_platform=")?.trim();
        (!rest.is_empty()).then(|| rest.to_string())
    })
}

/// Chassis serial: STATE_DB EEPROM (populated by pmon), then
/// `decode-syseeprom -s`, then DMI.
fn serial_number() -> Option<String> {
    // TLV type 0x23 = Serial Number in the ONIE EEPROM table.
    if let Ok(h) = hgetall(STATE_DB, "EEPROM_INFO|0x23") {
        if let Some(v) = h.get("Value").filter(|v| !v.is_empty()) {
            return Some(v.clone());
        }
    }
    if let Ok(out) = std::process::Command::new("decode-syseeprom").arg("-s").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    std::fs::read_to_string("/sys/class/dmi/id/product_serial")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ── interface counters (COUNTERS_DB) ─────────────────────────────────────────

/// One interface's cumulative traffic counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceCounters {
    pub name: String,
    pub bytes: u64,   // in + out octets
    pub packets: u64, // in + out unicast + non-unicast packets
}

/// The top `cap` interfaces by cumulative traffic, as PolicyStat entries for
/// the DeviceStats `top_policies` field (`name` = interface, `bytes`/`hits` =
/// octets/packets). Empty when COUNTERS_DB is unreachable.
pub fn top_interfaces(cap: usize) -> Vec<PolicyStat> {
    match read_interface_counters() {
        Ok(list) => rank_interfaces(list, cap),
        Err(e) => {
            tracing::debug!("interface counters unavailable: {e:#}");
            Vec::new()
        }
    }
}

fn read_interface_counters() -> Result<Vec<IfaceCounters>> {
    // COUNTERS_PORT_NAME_MAP: port name (Ethernet0) → SAI object id; the
    // per-port counters live at COUNTERS:<oid>.
    let name_map = hgetall(COUNTERS_DB, "COUNTERS_PORT_NAME_MAP")?;
    let mut conn = connection(COUNTERS_DB)?;
    let mut out = Vec::with_capacity(name_map.len());
    for (name, oid) in name_map {
        let counters: HashMap<String, String> = redis::cmd("HGETALL")
            .arg(format!("COUNTERS:{oid}"))
            .query(&mut conn)
            .unwrap_or_default();
        out.push(counters_for(name, &counters));
    }
    Ok(out)
}

/// Fold a COUNTERS:<oid> hash into the cumulative byte/packet totals. Missing
/// or unparsable fields count as 0 (platforms differ in which SAI counters
/// they populate).
pub fn counters_for(name: String, h: &HashMap<String, String>) -> IfaceCounters {
    let get = |k: &str| h.get(k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let bytes = get("SAI_PORT_STAT_IF_IN_OCTETS").saturating_add(get("SAI_PORT_STAT_IF_OUT_OCTETS"));
    let packets = get("SAI_PORT_STAT_IF_IN_UCAST_PKTS")
        .saturating_add(get("SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS"))
        .saturating_add(get("SAI_PORT_STAT_IF_OUT_UCAST_PKTS"))
        .saturating_add(get("SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS"));
    IfaceCounters { name, bytes, packets }
}

/// Pure half of `top_interfaces`: drop zero-traffic ports, sort descending by
/// bytes (ties broken by name for a stable order), cap.
pub fn rank_interfaces(mut list: Vec<IfaceCounters>, cap: usize) -> Vec<PolicyStat> {
    list.retain(|c| c.bytes > 0 || c.packets > 0);
    list.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
    list.truncate(cap);
    list.into_iter()
        .map(|c| PolicyStat { name: c.name, bytes: c.bytes, hits: c.packets })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn counters_sum_in_and_out() {
        let c = counters_for(
            "Ethernet0".into(),
            &h(&[
                ("SAI_PORT_STAT_IF_IN_OCTETS", "1000"),
                ("SAI_PORT_STAT_IF_OUT_OCTETS", "2500"),
                ("SAI_PORT_STAT_IF_IN_UCAST_PKTS", "10"),
                ("SAI_PORT_STAT_IF_OUT_UCAST_PKTS", "20"),
                ("SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS", "3"),
                ("SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS", "4"),
                ("SAI_PORT_STAT_IF_IN_ERRORS", "999"), // irrelevant field ignored
            ]),
        );
        assert_eq!(c.bytes, 3500);
        assert_eq!(c.packets, 37);
    }

    #[test]
    fn counters_tolerate_missing_and_garbage_fields() {
        let c = counters_for(
            "Ethernet4".into(),
            &h(&[("SAI_PORT_STAT_IF_IN_OCTETS", "not-a-number")]),
        );
        assert_eq!(c.bytes, 0);
        assert_eq!(c.packets, 0);
        let empty = counters_for("Ethernet8".into(), &HashMap::new());
        assert_eq!(empty.bytes, 0);
    }

    #[test]
    fn rank_sorts_filters_and_caps() {
        let list = vec![
            IfaceCounters { name: "Ethernet0".into(), bytes: 100, packets: 1 },
            IfaceCounters { name: "Ethernet4".into(), bytes: 9000, packets: 7 },
            IfaceCounters { name: "Ethernet8".into(), bytes: 0, packets: 0 }, // idle → dropped
            IfaceCounters { name: "Ethernet12".into(), bytes: 500, packets: 3 },
        ];
        let ranked = rank_interfaces(list, 2);
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].name, "Ethernet4");
        assert_eq!(ranked[0].bytes, 9000);
        assert_eq!(ranked[0].hits, 7);
        assert_eq!(ranked[1].name, "Ethernet12");
    }

    #[test]
    fn rank_is_stable_on_ties() {
        let list = vec![
            IfaceCounters { name: "Ethernet8".into(), bytes: 5, packets: 1 },
            IfaceCounters { name: "Ethernet0".into(), bytes: 5, packets: 1 },
        ];
        let ranked = rank_interfaces(list, 8);
        assert_eq!(ranked[0].name, "Ethernet0");
        assert_eq!(ranked[1].name, "Ethernet8");
    }

    #[test]
    fn parses_sonic_version_yml() {
        let yml = "build_version: '202311.140396'\ndebian_version: '12.1'\nkernel_version: '6.1.0'\n";
        assert_eq!(parse_sonic_version(yml).as_deref(), Some("202311.140396"));
        assert_eq!(
            parse_sonic_version("build_version: \"SONiC.master.0-abc\"\n").as_deref(),
            Some("SONiC.master.0-abc")
        );
        assert_eq!(parse_sonic_version("debian_version: '12.1'\n"), None);
        assert_eq!(parse_sonic_version(""), None);
    }
}
