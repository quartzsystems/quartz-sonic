//! Platform access for the feature modules added with the Configure →
//! Switching (STP / loop protection / LLDP / IGMP snooping) and Configure →
//! Routing (L3 / VRF / BGP / OSPF / IS-IS) pages: one trait covering the
//! SONiC redis databases, external commands (`config`, `vtysh`, `docker`),
//! and host files, so every feature backend runs unchanged against the real
//! switch or the in-memory mock the tests use.
//!
//! The older ports/VLAN/LAG code in `switching.rs` predates this trait and
//! talks to redis directly; new features go through `dyn Platform`.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};

/// Outcome of an external command, shell-free and mockable.
#[derive(Debug, Clone, Default)]
pub struct CmdOutput {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Everything a feature backend may touch on the switch. All methods are
/// blocking — callers run inside the management API's spawn_blocking.
pub trait Platform {
    fn hgetall(&mut self, db: i64, key: &str) -> Result<HashMap<String, String>>;
    fn scan(&mut self, db: i64, pattern: &str) -> Result<Vec<String>>;
    fn hset(&mut self, db: i64, key: &str, fields: &[(&str, &str)]) -> Result<()>;
    fn hdel(&mut self, db: i64, key: &str, fields: &[&str]) -> Result<()>;
    fn del(&mut self, db: i64, key: &str) -> Result<()>;
    fn exists(&mut self, db: i64, key: &str) -> Result<bool>;
    /// Run a command to completion and capture its output.
    fn run(&mut self, program: &str, args: &[&str]) -> Result<CmdOutput>;
    /// Run a command feeding `input` on stdin (chpasswd-style tools that
    /// refuse secrets on the command line, where they'd be visible in ps).
    fn run_input(&mut self, program: &str, args: &[&str], input: &str) -> Result<CmdOutput>;
    /// Start a command detached (for operations like the mgmt-VRF toggle that
    /// restart the very services a synchronous wait would hang on).
    fn spawn(&mut self, program: &str, args: &[&str]) -> Result<()>;
    fn read_file(&mut self, path: &str) -> Option<String>;
    fn write_file(&mut self, path: &str, content: &str) -> Result<()>;
}

// ── the real switch ─────────────────────────────────────────────────────────

/// [`Platform`] backed by the SONiC redis instance and the host. Connections
/// are opened lazily per database and reused for the request's lifetime.
#[derive(Default)]
pub struct SysPlatform {
    conns: HashMap<i64, redis::Connection>,
}

impl SysPlatform {
    pub fn new() -> Self {
        Self::default()
    }

    fn conn(&mut self, db: i64) -> Result<&mut redis::Connection> {
        if !self.conns.contains_key(&db) {
            self.conns.insert(db, super::connection(db)?);
        }
        Ok(self.conns.get_mut(&db).expect("just inserted"))
    }
}

impl Platform for SysPlatform {
    fn hgetall(&mut self, db: i64, key: &str) -> Result<HashMap<String, String>> {
        let conn = self.conn(db)?;
        redis::cmd("HGETALL")
            .arg(key)
            .query(conn)
            .with_context(|| format!("HGETALL {key} (db {db})"))
    }

    fn scan(&mut self, db: i64, pattern: &str) -> Result<Vec<String>> {
        let conn = self.conn(db)?;
        super::scan_keys(conn, pattern)
    }

    fn hset(&mut self, db: i64, key: &str, fields: &[(&str, &str)]) -> Result<()> {
        if fields.is_empty() {
            return Ok(());
        }
        let conn = self.conn(db)?;
        let mut cmd = redis::cmd("HSET");
        cmd.arg(key);
        for (f, v) in fields {
            cmd.arg(*f).arg(*v);
        }
        cmd.query(conn).with_context(|| format!("HSET {key} (db {db})"))
    }

    fn hdel(&mut self, db: i64, key: &str, fields: &[&str]) -> Result<()> {
        if fields.is_empty() {
            return Ok(());
        }
        let conn = self.conn(db)?;
        let mut cmd = redis::cmd("HDEL");
        cmd.arg(key);
        for f in fields {
            cmd.arg(*f);
        }
        cmd.query(conn).with_context(|| format!("HDEL {key} (db {db})"))
    }

    fn del(&mut self, db: i64, key: &str) -> Result<()> {
        let conn = self.conn(db)?;
        redis::cmd("DEL")
            .arg(key)
            .query(conn)
            .with_context(|| format!("DEL {key} (db {db})"))
    }

    fn exists(&mut self, db: i64, key: &str) -> Result<bool> {
        let conn = self.conn(db)?;
        let n: i64 = redis::cmd("EXISTS")
            .arg(key)
            .query(conn)
            .with_context(|| format!("EXISTS {key} (db {db})"))?;
        Ok(n > 0)
    }

    fn run(&mut self, program: &str, args: &[&str]) -> Result<CmdOutput> {
        let out = std::process::Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("run {program}"))?;
        Ok(CmdOutput {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn run_input(&mut self, program: &str, args: &[&str], input: &str) -> Result<CmdOutput> {
        use std::io::Write;
        let mut child = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .with_context(|| format!("run {program}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.as_bytes()).with_context(|| format!("write {program} stdin"))?;
        }
        let out = child.wait_with_output().with_context(|| format!("wait for {program}"))?;
        Ok(CmdOutput {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn spawn(&mut self, program: &str, args: &[&str]) -> Result<()> {
        std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| format!("spawn {program}"))?;
        Ok(())
    }

    fn read_file(&mut self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn write_file(&mut self, path: &str, content: &str) -> Result<()> {
        std::fs::write(path, content).with_context(|| format!("write {path}"))
    }
}

// ── degrading read helpers ──────────────────────────────────────────────────

/// A row that degrades to empty on any read failure — for the secondary
/// sources (APPL_DB/STATE_DB) whose absence must never fail a GET.
pub fn row(p: &mut dyn Platform, db: i64, key: &str) -> HashMap<String, String> {
    p.hgetall(db, key).unwrap_or_default()
}

/// Keys matching `pattern`, degrading to none on failure.
pub fn keys(p: &mut dyn Platform, db: i64, pattern: &str) -> Vec<String> {
    p.scan(db, pattern).unwrap_or_default()
}

/// A hash field, trimmed; None when absent or empty.
pub fn field<'a>(h: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    h.get(key).map(|v| v.trim()).filter(|v| !v.is_empty())
}

/// "Ethernet0" from "PORT|Ethernet0". None on an empty suffix.
pub fn key_suffix<'a>(key: &'a str, prefix: &str) -> Option<&'a str> {
    key.strip_prefix(prefix).filter(|s| !s.is_empty())
}

/// ("Vlan10", "Ethernet0") from "VLAN_MEMBER|Vlan10|Ethernet0" given the
/// "VLAN_MEMBER|" prefix. None unless both parts are non-empty. The second
/// part may itself contain separators (three-part BGP/OSPF keys split again).
pub fn two_parts<'a>(key: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let (a, b) = key.strip_prefix(prefix)?.split_once('|')?;
    (!a.is_empty() && !b.is_empty()).then_some((a, b))
}

/// (vrf, peer, af) from "BGP_NEIGHBOR_AF|default|10.0.0.1|ipv4_unicast".
pub fn three_parts<'a>(key: &'a str, prefix: &str) -> Option<(&'a str, &'a str, &'a str)> {
    let (a, rest) = key.strip_prefix(prefix)?.split_once('|')?;
    let (b, c) = rest.split_once('|')?;
    (!a.is_empty() && !b.is_empty() && !c.is_empty()).then_some((a, b, c))
}

// ── per-feature write serialization ─────────────────────────────────────────

/// Serialize CONFIG_DB write batches per feature so two proxied writes can't
/// interleave their diff-then-write sequences. Lock poisoning is ignored — a
/// panicked writer left no lock-protected in-memory state behind.
pub fn feature_lock(feature: &str) -> MutexGuard<'static, ()> {
    static STP: Mutex<()> = Mutex::new(());
    static LLDP: Mutex<()> = Mutex::new(());
    static IGMP: Mutex<()> = Mutex::new(());
    static L3: Mutex<()> = Mutex::new(());
    static BGP: Mutex<()> = Mutex::new(());
    static OSPF: Mutex<()> = Mutex::new(());
    static ISIS: Mutex<()> = Mutex::new(());
    static STATIC_ROUTES: Mutex<()> = Mutex::new(());
    static POLICY: Mutex<()> = Mutex::new(());
    static SYSTEM: Mutex<()> = Mutex::new(());
    static ACL: Mutex<()> = Mutex::new(());
    static AAA: Mutex<()> = Mutex::new(());
    static MIRROR: Mutex<()> = Mutex::new(());
    static STORM_CONTROL: Mutex<()> = Mutex::new(());
    static FDB: Mutex<()> = Mutex::new(());
    static DHCP_RELAY: Mutex<()> = Mutex::new(());
    static SFLOW: Mutex<()> = Mutex::new(());
    static MISC: Mutex<()> = Mutex::new(());
    let m = match feature {
        "stp" => &STP,
        "lldp" => &LLDP,
        "igmp" => &IGMP,
        "l3" => &L3,
        "bgp" => &BGP,
        "ospf" => &OSPF,
        "isis" => &ISIS,
        "static-routes" => &STATIC_ROUTES,
        "policy" => &POLICY,
        "system" => &SYSTEM,
        "acl" => &ACL,
        "aaa" => &AAA,
        "mirror" => &MIRROR,
        "storm-control" => &STORM_CONTROL,
        "fdb" => &FDB,
        "dhcp-relay" => &DHCP_RELAY,
        "sflow" => &SFLOW,
        _ => &MISC,
    };
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ── rollback batches ────────────────────────────────────────────────────────

/// A multi-row CONFIG_DB write that snapshots every key before first touching
/// it, so a mid-batch redis failure can restore the rows already written.
/// Rollback is best-effort — if redis died mid-batch the restore fails too,
/// and the caller's precise error is what surfaces.
pub struct Batch<'a> {
    plat: &'a mut dyn Platform,
    snapshots: Vec<(i64, String, HashMap<String, String>)>,
}

impl<'a> Batch<'a> {
    pub fn new(plat: &'a mut dyn Platform) -> Self {
        Self { plat, snapshots: Vec::new() }
    }

    fn snapshot(&mut self, db: i64, key: &str) -> Result<()> {
        if self.snapshots.iter().any(|(d, k, _)| *d == db && k == key) {
            return Ok(());
        }
        let prior = self.plat.hgetall(db, key)?;
        self.snapshots.push((db, key.to_string(), prior));
        Ok(())
    }

    pub fn hset(&mut self, db: i64, key: &str, fields: &[(&str, &str)]) -> Result<()> {
        self.snapshot(db, key)?;
        self.plat.hset(db, key, fields)
    }

    pub fn hdel(&mut self, db: i64, key: &str, fields: &[&str]) -> Result<()> {
        self.snapshot(db, key)?;
        self.plat.hdel(db, key, fields)
    }

    pub fn del(&mut self, db: i64, key: &str) -> Result<()> {
        self.snapshot(db, key)?;
        self.plat.del(db, key)
    }

    fn rollback(&mut self) {
        for (db, key, prior) in std::mem::take(&mut self.snapshots).into_iter().rev() {
            let _ = self.plat.del(db, &key);
            if !prior.is_empty() {
                let fields: Vec<(&str, &str)> =
                    prior.iter().map(|(f, v)| (f.as_str(), v.as_str())).collect();
                let _ = self.plat.hset(db, &key, &fields);
            }
        }
    }
}

/// Run `op` as a rolled-back-on-error batch.
pub fn apply(
    plat: &mut dyn Platform,
    op: impl FnOnce(&mut Batch) -> Result<()>,
) -> Result<()> {
    let mut batch = Batch::new(plat);
    match op(&mut batch) {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::warn!("write batch failed, rolling back: {e:#}");
            batch.rollback();
            Err(e)
        }
    }
}

// ── the in-memory mock (tests) ──────────────────────────────────────────────

#[cfg(test)]
pub mod mem {
    use std::collections::BTreeMap;

    use super::*;

    /// In-memory [`Platform`]: seeded redis content, canned command output,
    /// canned files, and an ordered log of every mutation and command — the
    /// tests assert on sequencing (e.g. the VRF rebind order) with it.
    #[derive(Default)]
    pub struct MemPlatform {
        pub dbs: HashMap<i64, BTreeMap<String, HashMap<String, String>>>,
        pub files: HashMap<String, String>,
        /// (command-prefix, output) — first prefix match wins; unmatched
        /// commands succeed with empty output.
        pub cmd_outputs: Vec<(Vec<String>, CmdOutput)>,
        pub log: Vec<String>,
        /// Stdin fed to run_input calls, in order (kept out of `log` — it
        /// carries secrets).
        pub stdins: Vec<String>,
        /// Fail exactly the Nth mutation (1-based) — later ones succeed, so
        /// rollback paths can be exercised (rollback tests).
        pub fail_at_write: Option<usize>,
        writes: usize,
    }

    impl MemPlatform {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn seed(&mut self, db: i64, key: &str, fields: &[(&str, &str)]) {
            let row = self.dbs.entry(db).or_default().entry(key.to_string()).or_default();
            for (f, v) in fields {
                row.insert(f.to_string(), v.to_string());
            }
        }

        pub fn seed_file(&mut self, path: &str, content: &str) {
            self.files.insert(path.to_string(), content.to_string());
        }

        pub fn on_cmd(&mut self, prefix: &[&str], out: CmdOutput) {
            self.cmd_outputs
                .push((prefix.iter().map(|s| s.to_string()).collect(), out));
        }

        pub fn row(&self, db: i64, key: &str) -> HashMap<String, String> {
            self.dbs
                .get(&db)
                .and_then(|m| m.get(key))
                .cloned()
                .unwrap_or_default()
        }

        pub fn has_key(&self, db: i64, key: &str) -> bool {
            self.dbs.get(&db).map(|m| m.contains_key(key)).unwrap_or(false)
        }

        fn write_gate(&mut self) -> Result<()> {
            self.writes += 1;
            if self.fail_at_write == Some(self.writes) {
                anyhow::bail!("injected write failure");
            }
            Ok(())
        }
    }

    /// Redis-glob match supporting `*` (the only wildcard the modules use).
    pub fn glob_match(pattern: &str, s: &str) -> bool {
        fn inner(p: &[u8], s: &[u8]) -> bool {
            match p.first() {
                None => s.is_empty(),
                Some(b'*') => {
                    (0..=s.len()).any(|i| inner(&p[1..], &s[i..]))
                }
                Some(&c) => s.first() == Some(&c) && inner(&p[1..], &s[1..]),
            }
        }
        inner(pattern.as_bytes(), s.as_bytes())
    }

    impl Platform for MemPlatform {
        fn hgetall(&mut self, db: i64, key: &str) -> Result<HashMap<String, String>> {
            Ok(self.row(db, key))
        }

        fn scan(&mut self, db: i64, pattern: &str) -> Result<Vec<String>> {
            Ok(self
                .dbs
                .get(&db)
                .map(|m| {
                    m.keys()
                        .filter(|k| glob_match(pattern, k))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default())
        }

        fn hset(&mut self, db: i64, key: &str, fields: &[(&str, &str)]) -> Result<()> {
            if fields.is_empty() {
                return Ok(());
            }
            self.write_gate()?;
            for (f, v) in fields {
                self.log.push(format!("HSET {db} {key} {f}={v}"));
            }
            self.seed(db, key, fields);
            Ok(())
        }

        fn hdel(&mut self, db: i64, key: &str, fields: &[&str]) -> Result<()> {
            if fields.is_empty() {
                return Ok(());
            }
            self.write_gate()?;
            for f in fields {
                self.log.push(format!("HDEL {db} {key} {f}"));
            }
            if let Some(row) = self.dbs.entry(db).or_default().get_mut(key) {
                for f in fields {
                    row.remove(*f);
                }
                if row.is_empty() {
                    self.dbs.entry(db).or_default().remove(key);
                }
            }
            Ok(())
        }

        fn del(&mut self, db: i64, key: &str) -> Result<()> {
            self.write_gate()?;
            self.log.push(format!("DEL {db} {key}"));
            self.dbs.entry(db).or_default().remove(key);
            Ok(())
        }

        fn exists(&mut self, db: i64, key: &str) -> Result<bool> {
            Ok(self.has_key(db, key))
        }

        fn run(&mut self, program: &str, args: &[&str]) -> Result<CmdOutput> {
            let mut full = vec![program.to_string()];
            full.extend(args.iter().map(|s| s.to_string()));
            self.log.push(format!("RUN {}", full.join(" ")));
            for (prefix, out) in &self.cmd_outputs {
                if full.len() >= prefix.len() && full[..prefix.len()] == prefix[..] {
                    return Ok(out.clone());
                }
            }
            Ok(CmdOutput { ok: true, ..Default::default() })
        }

        fn run_input(&mut self, program: &str, args: &[&str], input: &str) -> Result<CmdOutput> {
            // Stdin is captured separately, never logged with the command —
            // it carries secrets (chpasswd) even in tests.
            self.stdins.push(input.to_string());
            let mut full = vec![program.to_string()];
            full.extend(args.iter().map(|s| s.to_string()));
            self.log.push(format!("RUN-INPUT {}", full.join(" ")));
            for (prefix, out) in &self.cmd_outputs {
                if full.len() >= prefix.len() && full[..prefix.len()] == prefix[..] {
                    return Ok(out.clone());
                }
            }
            Ok(CmdOutput { ok: true, ..Default::default() })
        }

        fn spawn(&mut self, program: &str, args: &[&str]) -> Result<()> {
            self.log.push(format!("SPAWN {program} {}", args.join(" ")));
            Ok(())
        }

        fn read_file(&mut self, path: &str) -> Option<String> {
            self.files.get(path).cloned()
        }

        fn write_file(&mut self, path: &str, content: &str) -> Result<()> {
            self.log.push(format!("WRITE-FILE {path}"));
            self.files.insert(path.to_string(), content.to_string());
            Ok(())
        }
    }

    #[test]
    fn glob_matches_star_patterns() {
        assert!(glob_match("PORT|*", "PORT|Ethernet0"));
        assert!(glob_match("VLAN_MEMBER|Vlan10|*", "VLAN_MEMBER|Vlan10|Ethernet0"));
        assert!(!glob_match("PORT|*", "PORTCHANNEL|PortChannel1"));
        assert!(glob_match("*", "anything"));
        // STP_VLAN|* must not catch STP_VLAN_PORT rows (different table).
        assert!(!glob_match("STP_VLAN|*", "STP_VLAN_PORT|Vlan10|Ethernet0"));
    }
}
