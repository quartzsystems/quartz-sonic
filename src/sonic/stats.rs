//! Periodic device health & traffic telemetry.
//!
//! Every `INTERVAL` seconds the control channel asks this module for a
//! [`DeviceStats`] snapshot and pushes it up the existing ControlStream (see
//! `control::connected_wait`). Collection reads the box directly (the agent
//! runs as root); a source that is missing or unreadable degrades to a zero /
//! empty field for just that one gauge — the console renders partial
//! snapshots fine, so nothing here fails the whole message. The controller
//! stores these into per-device history and shows Used/Free/Total for
//! mem/disk, so the absolute byte figures are real readings, not derived
//! from the percentages.
//!
//! Field provenance:
//!   cpu_pct     — busy/total delta of /proc/stat's aggregate `cpu` line
//!                 across a short in-call sample window.
//!   mem_pct     — (MemTotal - MemAvailable) / MemTotal from /proc/meminfo.
//!   disk_pct    — used% of the root filesystem via statvfs(3) (Linux only).
//!   uptime_secs — first field of /proc/uptime.
//!   public_ip   — the source address the kernel picks for the default
//!                 route; "" when there is no route out.
//!   top_policies — the top interfaces by cumulative traffic from
//!                 COUNTERS_DB (`name` = interface, `bytes`/`hits` =
//!                 octets/packets), so the console's "most active" table
//!                 shows meaningful data for a switch.

use std::time::Duration;

use crate::proto::device::DeviceStats;
use crate::sonic;

/// How often the control channel emits a snapshot.
pub const INTERVAL: Duration = Duration::from_secs(30);

/// In-call CPU sample window. Short enough not to stall the collector's
/// blocking task, long enough for a stable busy/total ratio.
const CPU_SAMPLE: Duration = Duration::from_millis(200);

/// Cap on `top_policies` (the busiest interfaces; the console shows a
/// handful).
const MAX_INTERFACES: usize = 8;

/// Collect a full snapshot from the system's live sources.
pub fn collect() -> DeviceStats {
    // Read memory and root-fs usage once each; the gauge and the absolute
    // figures come from the same sample so they can't disagree.
    let mem = read_mem();
    let disk = read_disk("/");
    DeviceStats {
        time_unix: crate::state::now_unix(),
        interval_secs: INTERVAL.as_secs() as u32,
        cpu_pct: clamp_pct(sample_cpu_pct().unwrap_or(0.0)),
        mem_pct: clamp_pct(mem.map(|m| m.pct()).unwrap_or(0.0)),
        disk_pct: clamp_pct(disk.map(|d| d.pct).unwrap_or(0.0)),
        uptime_secs: read_uptime_secs().unwrap_or(0),
        public_ip: outbound_ip().unwrap_or_default(),
        top_policies: sonic::top_interfaces(MAX_INTERFACES),
        mem_used_bytes: mem.map(|m| m.used_bytes).unwrap_or(0),
        mem_total_bytes: mem.map(|m| m.total_bytes).unwrap_or(0),
        disk_used_bytes: disk.map(|d| d.used_bytes).unwrap_or(0),
        disk_total_bytes: disk.map(|d| d.total_bytes).unwrap_or(0),
    }
}

/// Clamp a gauge to the 0–100 range the contract promises.
fn clamp_pct(v: f64) -> f64 {
    if v.is_nan() {
        0.0
    } else {
        v.clamp(0.0, 100.0)
    }
}

// ── CPU ─────────────────────────────────────────────────────────────────────

/// Sample /proc/stat twice `CPU_SAMPLE` apart and return the busy percentage
/// over that window — a point-in-time reading, no persistent state needed.
fn sample_cpu_pct() -> Option<f64> {
    let first = cpu_snapshot(&std::fs::read_to_string("/proc/stat").ok()?)?;
    std::thread::sleep(CPU_SAMPLE);
    let second = cpu_snapshot(&std::fs::read_to_string("/proc/stat").ok()?)?;
    cpu_pct_from(first, second)
}

/// (busy, total) jiffies from the aggregate `cpu` line of /proc/stat. Busy is
/// everything except idle + iowait.
fn cpu_snapshot(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let vals: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|t| t.parse::<u64>().ok())
        .collect();
    // user, nice, system, idle, iowait, irq, softirq, steal, …
    if vals.len() < 4 {
        return None;
    }
    let total: u64 = vals.iter().sum();
    let idle = vals[3] + vals.get(4).copied().unwrap_or(0); // idle + iowait
    Some((total.saturating_sub(idle), total))
}

/// Busy percentage between two snapshots. None when the counters didn't
/// advance (total delta 0) — nothing to average over.
fn cpu_pct_from(prev: (u64, u64), cur: (u64, u64)) -> Option<f64> {
    let busy = cur.0.saturating_sub(prev.0) as f64;
    let total = cur.1.saturating_sub(prev.1) as f64;
    if total <= 0.0 {
        return None;
    }
    Some(busy / total * 100.0)
}

// ── memory ──────────────────────────────────────────────────────────────────

/// Memory figures in bytes: total is MemTotal, used is MemTotal -
/// MemAvailable (so free = MemAvailable). The `mem_pct` gauge is derived
/// from these, keeping the two in lockstep.
#[derive(Clone, Copy)]
struct MemStats {
    used_bytes: u64,
    total_bytes: u64,
}

impl MemStats {
    /// used / total * 100 — the `mem_pct` gauge. 0 when total is unknown.
    fn pct(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            self.used_bytes as f64 / self.total_bytes as f64 * 100.0
        }
    }
}

fn read_mem() -> Option<MemStats> {
    mem_from(&std::fs::read_to_string("/proc/meminfo").ok()?)
}

/// MemTotal and MemTotal - MemAvailable from /proc/meminfo (values in kB → bytes).
fn mem_from(meminfo: &str) -> Option<MemStats> {
    let field = |name: &str| -> Option<u64> {
        meminfo.lines().find_map(|l| {
            let rest = l.strip_prefix(name)?.strip_prefix(':')?;
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
    };
    let total = field("MemTotal")?;
    let available = field("MemAvailable")?;
    if total == 0 {
        return None;
    }
    Some(MemStats {
        used_bytes: total.saturating_sub(available) * 1024,
        total_bytes: total * 1024,
    })
}

// ── uptime ──────────────────────────────────────────────────────────────────

fn read_uptime_secs() -> Option<i64> {
    uptime_from(&std::fs::read_to_string("/proc/uptime").ok()?)
}

/// The integer seconds from the first field of /proc/uptime ("12345.67 …").
fn uptime_from(text: &str) -> Option<i64> {
    text.split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|s| s as i64)
}

// ── disk ────────────────────────────────────────────────────────────────────

/// Root-filesystem figures (`df` semantics): total is the whole filesystem,
/// used is total - free (reserved blocks included), and `pct` is `df`'s
/// Use% — used / (used + available), where available excludes root-reserved
/// blocks. Because reserved space is in `used` but not the pct denominator,
/// `used_bytes / total_bytes` need not equal `pct`.
#[derive(Clone, Copy)]
struct DiskStats {
    used_bytes: u64,
    total_bytes: u64,
    pct: f64,
}

#[cfg(target_os = "linux")]
fn read_disk(path: &str) -> Option<DiskStats> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: statvfs fills a zeroed struct and we only read it on rc == 0.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    disk_from(s.f_frsize as u64, s.f_blocks as u64, s.f_bfree as u64, s.f_bavail as u64)
}

#[cfg(not(target_os = "linux"))]
fn read_disk(_path: &str) -> Option<DiskStats> {
    None // statvfs is Linux-only; the daemon runs on SONiC.
}

/// Pure half of `read_disk`: fold the statvfs block counts into byte totals and
/// `df`'s Use%. `frsize` is the fundamental block size (df's unit). None when
/// there's nothing to divide by (no used-or-available blocks).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // read_disk stubs out off-Linux
fn disk_from(frsize: u64, blocks: u64, bfree: u64, bavail: u64) -> Option<DiskStats> {
    let used_blocks = blocks.saturating_sub(bfree);
    let denom = used_blocks + bavail; // df's Use% denominator (excludes reserved)
    if denom == 0 {
        return None;
    }
    Some(DiskStats {
        used_bytes: used_blocks * frsize,
        total_bytes: blocks * frsize,
        pct: used_blocks as f64 / denom as f64 * 100.0,
    })
}

// ── public IP ─────────────────────────────────────────────────────────────────

/// The source address the kernel would use to reach the public internet — the
/// address the switch reports for itself. `connect` on a UDP socket only does
/// the route lookup and binds a source; it sends nothing. None when there is
/// no default route (or only a loopback source).
fn outbound_ip() -> Option<String> {
    // IPv4 default route first, then IPv6.
    outbound_ip_via("1.1.1.1:80").or_else(|| outbound_ip_via("[2606:4700:4700::1111]:80"))
}

fn outbound_ip_via(dest: &str) -> Option<String> {
    let bind = if dest.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" };
    let sock = std::net::UdpSocket::bind(bind).ok()?;
    sock.connect(dest).ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    Some(ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_percentage_from_two_snapshots() {
        // total advances 100, busy advances 25 → 25%.
        let a = (100, 400);
        let b = (125, 500);
        assert_eq!(cpu_pct_from(a, b), Some(25.0));
        // No advance → None (nothing to average).
        assert_eq!(cpu_pct_from(b, b), None);
    }

    #[test]
    fn cpu_snapshot_parses_aggregate_line() {
        let stat = "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\nintr 999\n";
        // total = 1000, idle+iowait = 800+50 = 850, busy = 150.
        assert_eq!(cpu_snapshot(stat), Some((150, 1000)));
        assert_eq!(cpu_snapshot("garbage\n"), None);
    }

    #[test]
    fn mem_bytes_and_pct_from_meminfo() {
        let meminfo = "MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    250 kB\nBuffers:  0 kB\n";
        let mem = mem_from(meminfo).expect("parses");
        // kB → bytes; used = (1000 - 250) kB = 750 kB.
        assert_eq!(mem.total_bytes, 1000 * 1024);
        assert_eq!(mem.used_bytes, 750 * 1024);
        // The gauge is derived from the same bytes: 750/1000 = 75%.
        assert_eq!(mem.pct(), 75.0);
        assert!(mem_from("MemTotal: 0 kB\nMemAvailable: 0 kB\n").is_none());
        assert!(mem_from("nope\n").is_none());
    }

    #[test]
    fn disk_bytes_and_pct_from_statvfs_blocks() {
        // 4 KiB blocks: 100 total, 40 free, 30 available (10 blocks reserved).
        let d = disk_from(4096, 100, 40, 30).expect("computes");
        // total = 100 blocks, used = 60 blocks.
        assert_eq!(d.total_bytes, 100 * 4096);
        assert_eq!(d.used_bytes, 60 * 4096);
        // df Use% = used / (used + avail) = 60 / 90 → 66.66…%, not used/total.
        assert!((d.pct - 66.666_666).abs() < 1e-4);
        // Empty filesystem (no used or available blocks) → None.
        assert!(disk_from(4096, 0, 0, 0).is_none());
    }

    #[test]
    fn uptime_takes_the_first_field_as_seconds() {
        assert_eq!(uptime_from("12345.67 98765.43\n"), Some(12345));
        assert_eq!(uptime_from("0.00 0.00"), Some(0));
        assert_eq!(uptime_from(""), None);
    }

    #[test]
    fn clamp_keeps_gauges_in_range() {
        assert_eq!(clamp_pct(-5.0), 0.0);
        assert_eq!(clamp_pct(150.0), 100.0);
        assert_eq!(clamp_pct(42.5), 42.5);
        assert_eq!(clamp_pct(f64::NAN), 0.0);
    }

    /// Compile-time guard for the wrapping `control.rs` uses to put a
    /// snapshot on the ControlStream.
    #[test]
    fn snapshot_wraps_into_a_device_message() {
        use crate::proto::device::{device_message, DeviceMessage};
        let snapshot = DeviceStats {
            time_unix: 1,
            interval_secs: INTERVAL.as_secs() as u32,
            ..Default::default()
        };
        let msg = DeviceMessage {
            msg: Some(device_message::Msg::DeviceStats(snapshot)),
        };
        assert!(matches!(msg.msg, Some(device_message::Msg::DeviceStats(_))));
    }
}
