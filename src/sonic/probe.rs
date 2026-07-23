//! The capability probe: what this SONiC image can actually do, so every
//! feature GET can lead with an honest `capability` envelope and no write
//! ever lands in a CONFIG_DB table no daemon on the image consumes.
//!
//! One agent binary supports old community SONiC, new community SONiC
//! (202505+), and Enterprise SONiC (Dell/Broadcom). The probe detects, at
//! startup (first use) and on demand:
//!   - SONiC release + flavor from /etc/sonic/sonic_version.yml build
//!     metadata (enterprise forks version like "4.1.1" and/or say so),
//!   - FEATURE table entries and running dockers (stp, lldp, bgp),
//!   - DEVICE_METADATA|localhost: docker_routing_config_mode,
//!     frr_mgmt_framework_config, bgp_asn,
//!   - which FRR daemons vtysh can see (ospfd/isisd presence).
//!
//! Gathering runs `docker ps` and `vtysh` — results are cached for a short
//! TTL so a burst of console page loads probes once.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::store::{field, key_suffix, keys, row, Platform};
use super::CONFIG_DB;

/// The envelope every feature document starts with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capability {
    pub supported: bool,
    pub read_only: bool,
    pub reason: Option<String>,
}

impl Capability {
    pub fn yes() -> Self {
        Self { supported: true, read_only: false, reason: None }
    }

    pub fn yes_with_reason(reason: impl Into<String>) -> Self {
        Self { supported: true, read_only: false, reason: Some(reason.into()) }
    }

    pub fn no(reason: impl Into<String>) -> Self {
        Self { supported: false, read_only: false, reason: Some(reason.into()) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpMode {
    Frrcfgd,
    Legacy,
    Unavailable,
}

impl BgpMode {
    pub fn as_str(self) -> &'static str {
        match self {
            BgpMode::Frrcfgd => "frrcfgd",
            BgpMode::Legacy => "legacy",
            BgpMode::Unavailable => "unavailable",
        }
    }
}

/// One probe's findings. Everything downstream derives from this snapshot so
/// feature gating is a pure function of it (and unit-testable per profile).
#[derive(Debug, Clone, Default)]
pub struct Probe {
    pub enterprise: bool,
    pub build_version: Option<String>,
    /// Community release train as YYYYMM (202311, 202505, …); None on master
    /// and enterprise builds.
    pub release: Option<u32>,
    /// FEATURE|<name> → state.
    pub features: HashMap<String, String>,
    /// Container names from `docker ps`.
    pub dockers: Vec<String>,
    /// DEVICE_METADATA|localhost docker_routing_config_mode ("separated"
    /// when unset — SONiC's default).
    pub routing_mode: String,
    /// DEVICE_METADATA|localhost frr_mgmt_framework_config == "true".
    pub frr_mgmt: bool,
    /// DEVICE_METADATA|localhost bgp_asn.
    pub bgp_asn: Option<u64>,
    /// Daemons listed by `vtysh -c "show daemons"`.
    pub frr_daemons: Vec<String>,
}

impl Probe {
    /// The FEATURE table knows this feature (whatever its state) — i.e. the
    /// image was built with it.
    pub fn has_feature(&self, name: &str) -> bool {
        self.features.contains_key(name)
    }

    pub fn feature_enabled(&self, name: &str) -> bool {
        matches!(
            self.features.get(name).map(String::as_str),
            Some("enabled") | Some("always_enabled")
        )
    }

    pub fn docker_running(&self, name: &str) -> bool {
        self.dockers.iter().any(|d| d == name)
    }

    fn frr_daemon(&self, name: &str) -> bool {
        self.frr_daemons.iter().any(|d| d == name)
    }

    /// STP backend present: community docker-stp / the stp feature (202505+
    /// built with INCLUDE_STP), or the enterprise vendor STP stack.
    pub fn stp_supported(&self) -> bool {
        self.enterprise || self.has_feature("stp") || self.docker_running("stp")
    }

    /// MSTP exists on enterprise and community master+ (no release train yet
    /// carries it); every STP backend does PVST.
    pub fn stp_modes(&self) -> Vec<&'static str> {
        if !self.stp_supported() {
            return Vec::new();
        }
        let mut modes = vec!["pvst"];
        if self.enterprise || self.release.is_none() {
            modes.push("mst");
        }
        modes
    }

    pub fn lldp_supported(&self) -> bool {
        self.has_feature("lldp") || self.docker_running("lldp")
    }

    /// LLDP timers/system-name are only configurable where a management
    /// stack consumes the LLDP|GLOBAL CONFIG_DB table (enterprise);
    /// community's lldpmgrd ignores it.
    pub fn lldp_timers_supported(&self) -> bool {
        self.enterprise
    }

    /// IGMP snooping: the community L2MC HLD never merged.
    pub fn igmp_snooping_supported(&self) -> bool {
        self.enterprise
    }

    pub fn bgp_available(&self) -> bool {
        self.has_feature("bgp") || self.docker_running("bgp")
    }

    pub fn bgp_mode(&self) -> BgpMode {
        if !self.bgp_available() {
            BgpMode::Unavailable
        } else if self.frr_mgmt {
            BgpMode::Frrcfgd
        } else {
            BgpMode::Legacy
        }
    }

    /// ospfd only runs under frr_mgmt_framework on community images;
    /// enterprise OSPF counts when its daemon is actually there.
    pub fn ospf_supported(&self) -> bool {
        (self.frr_mgmt && self.bgp_available())
            || (self.enterprise && (self.frr_daemon("ospfd") || self.bgp_available()))
    }

    /// isisd is not even started in the community FRR container; only images
    /// that run it (enterprise/custom) can be managed via vtysh.
    pub fn isis_supported(&self) -> bool {
        self.frr_daemon("isisd")
    }

    /// Mirroring itself is core orchagent on every image; SPAN-type sessions
    /// (`type=SPAN`, dst_port) only landed in 202012. Master and enterprise
    /// builds count as newest.
    pub fn span_mirror_supported(&self) -> bool {
        self.enterprise || self.release.is_none_or(|r| r >= 202012)
    }

    /// PORT_STORM_CONTROL orchagent support merged for community 202205;
    /// enterprise carries its own BUM storm control against the same table.
    pub fn storm_control_supported(&self) -> bool {
        self.enterprise || self.release.is_none_or(|r| r >= 202205)
    }

    /// The MAC-table config knobs — SWITCH|switch `fdb_aging_time` and
    /// static CONFIG_DB FDB entries (`config mac …`) — are consumed by
    /// orchagent since community 202205 (and on enterprise). Older images
    /// show the learned table read-only.
    pub fn fdb_config_writable(&self) -> bool {
        self.enterprise || self.release.is_none_or(|r| r >= 202205)
    }

    /// DHCP relay needs the dhcp_relay container to consume the VLANs'
    /// dhcp_servers lists.
    pub fn dhcp_relay_supported(&self) -> bool {
        self.has_feature("dhcp_relay") || self.docker_running("dhcp_relay")
    }

    /// sFlow is configurable when the image ships the feature at all; the
    /// caller downgrades to read-only when the docker isn't running.
    pub fn sflow_present(&self) -> bool {
        self.has_feature("sflow") || self.docker_running("sflow")
    }

    /// MCLAG needs iccpd consuming MCLAG_DOMAIN: enterprise stacks ship it,
    /// community images only when built with the mclag feature.
    pub fn mclag_supported(&self) -> bool {
        self.enterprise
            || self.has_feature("mclag")
            || self.has_feature("iccpd")
            || self.docker_running("iccpd")
            || self.docker_running("mclag")
    }

    /// vrrpd only ships on enterprise images (or community builds that
    /// expose a vrrp feature).
    pub fn vrrp_supported(&self) -> bool {
        self.enterprise || self.has_feature("vrrp") || self.docker_running("vrrp")
    }

    /// BFD is programmed via FRR's bfdd inside the bgp container.
    pub fn bfd_supported(&self) -> bool {
        self.bgp_available() && self.frr_daemon("bfdd")
    }

    /// VXLAN orchestration (VXLAN_TUNNEL / VXLAN_TUNNEL_MAP) landed for
    /// community 202012; enterprise and master builds count as newest.
    pub fn vxlan_supported(&self) -> bool {
        self.enterprise || self.release.is_none_or(|r| r >= 202012)
    }

    /// FRR changes need `vtysh -c "write memory"` only when FRR owns its own
    /// config file (split modes); in unified/separated modes CONFIG_DB is the
    /// source of truth and `config save` covers persistence.
    pub fn frr_write_memory_needed(&self) -> bool {
        matches!(self.routing_mode.as_str(), "split" | "split-unified")
    }
}

// ── gathering ───────────────────────────────────────────────────────────────

/// Probe the platform now (no cache).
pub fn gather(plat: &mut dyn Platform) -> Probe {
    let yml = plat.read_file("/etc/sonic/sonic_version.yml").unwrap_or_default();
    let mut features = HashMap::new();
    for key in keys(plat, CONFIG_DB, "FEATURE|*") {
        if let Some(name) = key_suffix(&key, "FEATURE|") {
            let state = field(&row(plat, CONFIG_DB, &key), "state").unwrap_or("").to_string();
            features.insert(name.to_string(), state);
        }
    }
    let meta = row(plat, CONFIG_DB, "DEVICE_METADATA|localhost");
    let dockers = plat
        .run("docker", &["ps", "--format", "{{.Names}}"])
        .ok()
        .filter(|o| o.ok)
        .map(|o| o.stdout.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default();
    let frr_daemons = plat
        .run("vtysh", &["-c", "show daemons"])
        .ok()
        .filter(|o| o.ok)
        .map(|o| o.stdout.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    let probe = assemble(&yml, features, dockers, &meta, frr_daemons);
    tracing::debug!(
        enterprise = probe.enterprise,
        build_version = probe.build_version.as_deref().unwrap_or("unknown"),
        release = probe.release,
        frr_mgmt = probe.frr_mgmt,
        routing_mode = %probe.routing_mode,
        "capability probe"
    );
    probe
}

/// Pure assembly from raw findings — the unit the per-profile tests drive.
pub fn assemble(
    version_yml: &str,
    features: HashMap<String, String>,
    dockers: Vec<String>,
    device_metadata: &HashMap<String, String>,
    frr_daemons: Vec<String>,
) -> Probe {
    let build_version = super::parse_sonic_version(version_yml);
    Probe {
        enterprise: is_enterprise(version_yml, build_version.as_deref()),
        release: build_version.as_deref().and_then(release_of),
        build_version,
        features,
        dockers,
        routing_mode: field(device_metadata, "docker_routing_config_mode")
            .unwrap_or("separated")
            .to_string(),
        frr_mgmt: field(device_metadata, "frr_mgmt_framework_config")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        bgp_asn: field(device_metadata, "bgp_asn").and_then(|v| v.parse().ok()),
        frr_daemons,
    }
}

/// Enterprise forks either say so in the version metadata or version like
/// "4.1.1" (small-major semver, vs community's date trains and SONiC.master
/// strings). `asic_type: broadcom` appears on community images too, so only
/// explicit "enterprise" wording counts, never vendor names.
pub fn is_enterprise(version_yml: &str, build_version: Option<&str>) -> bool {
    if version_yml.to_ascii_lowercase().contains("enterprise") {
        return true;
    }
    let Some(v) = build_version else { return false };
    let mut parts = v.split('.');
    let Some(major) = parts.next().and_then(|p| p.parse::<u32>().ok()) else {
        return false;
    };
    // 4.1.1 → enterprise; 202311.140396 → community date train.
    major < 2000 && parts.next().map(|p| p.bytes().all(|b| b.is_ascii_digit())).unwrap_or(false)
}

/// The community release train (YYYYMM) out of a build version like
/// "202311.140396" or "SONiC.202505-…". None for master/HEAD builds.
pub fn release_of(build_version: &str) -> Option<u32> {
    let bytes = build_version.as_bytes();
    for i in 0..bytes.len().saturating_sub(5) {
        if bytes[i..i + 6].iter().all(u8::is_ascii_digit)
            && (i == 0 || !bytes[i - 1].is_ascii_digit())
            && (i + 6 == bytes.len() || !bytes[i + 6].is_ascii_digit())
        {
            let n: u32 = build_version[i..i + 6].parse().ok()?;
            if (201700..=209912).contains(&n) {
                return Some(n);
            }
        }
    }
    None
}

// ── cache ───────────────────────────────────────────────────────────────────

const CACHE_TTL: Duration = Duration::from_secs(15);

static CACHE: Mutex<Option<(Instant, Probe)>> = Mutex::new(None);

/// The current probe, refreshed when older than the TTL. Feature GETs call
/// this so a console page load (several endpoints at once) probes once.
/// Under `cfg(test)` the cache is bypassed — parallel tests each drive their
/// own mock platform and must never see another test's probe.
pub fn current(plat: &mut dyn Platform) -> Probe {
    #[cfg(test)]
    return gather(plat);
    #[cfg(not(test))]
    current_cached(plat)
}

#[cfg(not(test))]
fn current_cached(plat: &mut dyn Platform) -> Probe {
    let mut cache = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((at, probe)) = cache.as_ref() {
        if at.elapsed() < CACHE_TTL {
            return probe.clone();
        }
    }
    let probe = gather(plat);
    *cache = Some((Instant::now(), probe.clone()));
    probe
}

/// Drop the cached probe so the next `current()` re-detects (used after
/// writes that change what the image runs, e.g. `config feature state`).
pub fn invalidate() {
    *CACHE.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn community(release: &str, features: &[&str], frr_mgmt: bool) -> Probe {
        let yml = format!("build_version: '{release}'\nasic_type: broadcom\n");
        let feats = features.iter().map(|f| (f.to_string(), "enabled".to_string())).collect();
        let meta = if frr_mgmt {
            h(&[("frr_mgmt_framework_config", "true"), ("bgp_asn", "65100")])
        } else {
            h(&[("bgp_asn", "65100")])
        };
        assemble(&yml, feats, vec![], &meta, vec![])
    }

    #[test]
    fn old_community_profile() {
        // Old community: no STP backend, flat BGP, no OSPF/IS-IS management.
        let p = community("202311.140396", &["lldp", "bgp"], false);
        assert!(!p.enterprise);
        assert_eq!(p.release, Some(202311));
        assert!(!p.stp_supported());
        assert!(p.stp_modes().is_empty());
        assert!(p.lldp_supported());
        assert!(!p.lldp_timers_supported());
        assert!(!p.igmp_snooping_supported());
        assert_eq!(p.bgp_mode(), BgpMode::Legacy);
        assert!(!p.ospf_supported());
        assert!(!p.isis_supported());
    }

    #[test]
    fn new_community_profile_with_and_without_stp() {
        let with = community("202505.12", &["lldp", "bgp", "stp"], false);
        assert_eq!(with.release, Some(202505));
        assert!(with.stp_supported());
        assert_eq!(with.stp_modes(), vec!["pvst"]); // no MSTP on a release train
        let without = community("202505.12", &["lldp", "bgp"], false);
        assert!(!without.stp_supported());
    }

    #[test]
    fn master_community_gets_mst() {
        let p = community("SONiC.master.601-1a2b3c", &["stp", "bgp", "lldp"], true);
        assert_eq!(p.release, None);
        assert_eq!(p.stp_modes(), vec!["pvst", "mst"]);
        assert_eq!(p.bgp_mode(), BgpMode::Frrcfgd);
        assert!(p.ospf_supported());
    }

    #[test]
    fn enterprise_profile() {
        let yml = "build_version: '4.1.1'\nrelease: 'Enterprise SONiC OS'\n";
        let p = assemble(
            yml,
            h(&[("lldp", "enabled"), ("bgp", "enabled")]),
            vec!["bgp".into(), "lldp".into()],
            &h(&[("bgp_asn", "65000"), ("frr_mgmt_framework_config", "true")]),
            vec!["zebra".into(), "bgpd".into(), "ospfd".into(), "isisd".into()],
        );
        assert!(p.enterprise);
        assert_eq!(p.release, None);
        assert!(p.stp_supported());
        assert_eq!(p.stp_modes(), vec!["pvst", "mst"]);
        assert!(p.lldp_timers_supported());
        assert!(p.igmp_snooping_supported());
        assert_eq!(p.bgp_mode(), BgpMode::Frrcfgd);
        assert!(p.ospf_supported());
        assert!(p.isis_supported());
    }

    #[test]
    fn enterprise_detection_ignores_vendor_asic_names() {
        // Community Broadcom build must stay community.
        assert!(!is_enterprise("build_version: '202311.1'\nasic_type: broadcom\n", Some("202311.1")));
        assert!(is_enterprise("build_version: '4.1.1'\n", Some("4.1.1")));
        assert!(is_enterprise(
            "build_version: 'SONiC.4.x'\nrelease: 'Dell Enterprise SONiC'\n",
            Some("SONiC.4.x")
        ));
        assert!(!is_enterprise("build_version: 'SONiC.master.1'\n", Some("SONiC.master.1")));
    }

    #[test]
    fn frrcfgd_toggle_selects_bgp_mode() {
        let legacy = community("202311.1", &["bgp"], false);
        assert_eq!(legacy.bgp_mode(), BgpMode::Legacy);
        let frr = community("202311.1", &["bgp"], true);
        assert_eq!(frr.bgp_mode(), BgpMode::Frrcfgd);
        let none = community("202311.1", &["lldp"], true);
        assert_eq!(none.bgp_mode(), BgpMode::Unavailable);
    }

    #[test]
    fn ha_overlay_capabilities() {
        let old = community("202311.140396", &["lldp", "bgp"], false);
        assert!(!old.mclag_supported());
        assert!(!old.vrrp_supported());
        assert!(!old.bfd_supported()); // bfdd not in `show daemons`
        assert!(old.vxlan_supported()); // 202311 >= 202012
        assert!(!community("201911.5", &["bgp"], false).vxlan_supported());
        let with_features = community("202505.12", &["bgp", "mclag", "vrrp"], false);
        assert!(with_features.mclag_supported());
        assert!(with_features.vrrp_supported());
        // bfdd counts once vtysh lists it (and the bgp container exists).
        let with_bfdd = assemble(
            "build_version: '202311.1'\n",
            h(&[("bgp", "enabled")]),
            vec![],
            &h(&[]),
            vec!["zebra".into(), "bgpd".into(), "bfdd".into()],
        );
        assert!(with_bfdd.bfd_supported());
        // Enterprise ships the whole HA stack.
        let enterprise = assemble(
            "build_version: '4.1.1'\nrelease: 'Enterprise SONiC OS'\n",
            HashMap::new(),
            vec![],
            &h(&[]),
            vec![],
        );
        assert!(enterprise.mclag_supported());
        assert!(enterprise.vrrp_supported());
        assert!(enterprise.vxlan_supported());
    }

    #[test]
    fn release_parsing() {
        assert_eq!(release_of("202311.140396"), Some(202311));
        assert_eq!(release_of("SONiC.202505-dirty"), Some(202505));
        assert_eq!(release_of("SONiC.master.601"), None);
        assert_eq!(release_of("4.1.1"), None);
        // 140396 is six digits but not a plausible train.
        assert_eq!(release_of("140396"), None);
    }

    #[test]
    fn write_memory_only_in_split_modes() {
        let mut p = Probe::default();
        for (mode, want) in [
            ("separated", false),
            ("unified", false),
            ("split", true),
            ("split-unified", true),
        ] {
            p.routing_mode = mode.to_string();
            assert_eq!(p.frr_write_memory_needed(), want, "{mode}");
        }
    }
}
