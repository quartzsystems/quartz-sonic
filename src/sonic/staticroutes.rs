//! Static routes for the console's Configure → Routing → Static Routes page.
//!
//! Backed by the CONFIG_DB `STATIC_ROUTE` table, rendered into FRR staticd by
//! bgpcfgd. Keys are `vrf|prefix` (SONiC's own sample configs use the literal
//! vrf "default" here) or a bare `prefix` for the default VRF; the hop list
//! lives in parallel comma-separated fields (`nexthop`, `ifname`,
//! `nexthop-vrf`, `distance`, `blackhole`) aligned by index.
//!
//! The console never sees the key encoding: routes carry `vrf: null` for the
//! default VRF, and a PUT replaces the whole row for its (vrf, prefix) —
//! including the alternate default-VRF spelling, so an upsert can never leave
//! both `PREFIX` and `default|PREFIX` rows behind.

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::probe::{self, Capability};
use super::store::{self, field, key_suffix, row, two_parts, Platform};
use super::switching::{natural_cmp, WriteError, WriteResult};
use super::CONFIG_DB;

const UNSUPPORTED: &str =
    "static routes require the bgp container (staticd), which is not running on this image";

fn bad(msg: impl Into<String>) -> WriteError {
    WriteError::BadRequest(msg.into())
}

fn capability(plat: &mut dyn Platform) -> Capability {
    if probe::current(plat).bgp_available() {
        Capability::yes()
    } else {
        Capability::no(UNSUPPORTED)
    }
}

fn require_supported(plat: &mut dyn Platform) -> WriteResult {
    if !probe::current(plat).bgp_available() {
        return Err(WriteError::Conflict(UNSUPPORTED.to_string()));
    }
    Ok(())
}

// ── document shapes ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextHop {
    pub gateway: Option<String>,
    pub interface: Option<String>,
    pub nexthop_vrf: Option<String>,
    #[serde(default)]
    pub blackhole: bool,
    pub distance: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteInput {
    pub vrf: Option<String>,
    pub prefix: String,
    pub next_hops: Vec<NextHop>,
}

#[derive(Debug, Deserialize)]
pub struct RouteKey {
    pub vrf: Option<String>,
    pub prefix: String,
}

// ── row ↔ hop-list codec (pure) ─────────────────────────────────────────────

/// Split one comma-separated field into per-hop slots, padded with "" to
/// `n` entries (SONiC leaves trailing slots off some fields).
fn slots(v: Option<&str>, n: usize) -> Vec<String> {
    let mut out: Vec<String> =
        v.unwrap_or("").split(',').map(|s| s.trim().to_string()).collect();
    out.resize(n.max(out.len()), String::new());
    out
}

/// Decode a STATIC_ROUTE row's parallel fields into hops. Pure.
pub fn hops_from_row(r: &std::collections::HashMap<String, String>) -> Vec<NextHop> {
    let count = ["nexthop", "ifname", "nexthop-vrf", "distance", "blackhole"]
        .iter()
        .filter_map(|f| field(r, f))
        .map(|v| v.split(',').count())
        .max()
        .unwrap_or(0);
    let gw = slots(field(r, "nexthop"), count);
    let ifname = slots(field(r, "ifname"), count);
    let nh_vrf = slots(field(r, "nexthop-vrf"), count);
    let dist = slots(field(r, "distance"), count);
    let bh = slots(field(r, "blackhole"), count);
    (0..count)
        .map(|i| NextHop {
            gateway: (!gw[i].is_empty()).then(|| gw[i].clone()),
            interface: (!ifname[i].is_empty()).then(|| ifname[i].clone()),
            nexthop_vrf: (!nh_vrf[i].is_empty()).then(|| nh_vrf[i].clone()),
            blackhole: bh[i].eq_ignore_ascii_case("true"),
            // SONiC writes distance 0 for "unset" — FRR's default (1) applies.
            distance: dist[i].parse::<u32>().ok().filter(|&d| d > 0),
        })
        .collect()
}

/// Encode hops back into the row's parallel fields. Pure.
pub fn row_from_hops(hops: &[NextHop]) -> Vec<(&'static str, String)> {
    let join = |f: fn(&NextHop) -> String| {
        hops.iter().map(f).collect::<Vec<_>>().join(",")
    };
    vec![
        ("nexthop", join(|h| h.gateway.clone().unwrap_or_default())),
        ("ifname", join(|h| h.interface.clone().unwrap_or_default())),
        ("nexthop-vrf", join(|h| h.nexthop_vrf.clone().unwrap_or_default())),
        ("distance", join(|h| h.distance.unwrap_or(0).to_string())),
        ("blackhole", join(|h| if h.blackhole { "true".into() } else { "false".into() })),
    ]
}

// ── GET /api/routing/static-routes ──────────────────────────────────────────

#[derive(Debug, Serialize)]
struct RouteDoc {
    vrf: Option<String>,
    prefix: String,
    next_hops: Vec<NextHop>,
}

pub fn get(plat: &mut dyn Platform) -> anyhow::Result<serde_json::Value> {
    let capability = capability(plat);
    let mut routes = Vec::new();
    for key in plat.scan(CONFIG_DB, "STATIC_ROUTE|*")? {
        let (vrf, prefix) = match two_parts(&key, "STATIC_ROUTE|") {
            Some((vrf, prefix)) => {
                ((vrf != "default").then(|| vrf.to_string()), prefix.to_string())
            }
            None => match key_suffix(&key, "STATIC_ROUTE|") {
                Some(prefix) => (None, prefix.to_string()),
                None => continue,
            },
        };
        let r = row(plat, CONFIG_DB, &key);
        routes.push(RouteDoc { vrf, prefix, next_hops: hops_from_row(&r) });
    }
    routes.sort_by(|a, b| {
        a.vrf
            .as_deref()
            .unwrap_or("")
            .cmp(b.vrf.as_deref().unwrap_or(""))
            .then_with(|| natural_cmp(&a.prefix, &b.prefix))
    });
    Ok(json!({ "capability": capability, "routes": routes }))
}

// ── validation ──────────────────────────────────────────────────────────────

/// A prefix usable in a STATIC_ROUTE key: parseable IP CIDR, no separators
/// that would corrupt the key.
fn check_prefix(prefix: &str) -> std::result::Result<(), String> {
    let err = || format!("invalid prefix {prefix:?} (expected an IPv4 or IPv6 CIDR)");
    let (ip, len) = prefix.split_once('/').ok_or_else(err)?;
    let ip: std::net::IpAddr = ip.parse().map_err(|_| err())?;
    let len: u8 = len.parse().map_err(|_| err())?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if len > max {
        return Err(err());
    }
    Ok(())
}

fn check_route(plat: &mut dyn Platform, route: &RouteInput) -> WriteResult {
    check_prefix(&route.prefix).map_err(bad)?;
    check_vrf(plat, route.vrf.as_deref())?;
    if route.next_hops.is_empty() {
        return Err(bad("a static route needs at least one next hop"));
    }
    for h in &route.next_hops {
        if h.blackhole && (h.gateway.is_some() || h.interface.is_some()) {
            return Err(bad("a blackhole hop cannot also have a gateway or interface"));
        }
        if !h.blackhole && h.gateway.is_none() && h.interface.is_none() {
            return Err(bad("each next hop needs a gateway and/or interface, or blackhole"));
        }
        if let Some(gw) = &h.gateway {
            if gw.parse::<std::net::IpAddr>().is_err() {
                return Err(bad(format!("invalid gateway {gw:?}")));
            }
        }
        for s in [&h.interface, &h.nexthop_vrf].into_iter().flatten() {
            if s.is_empty() || s.contains(',') || s.contains('|') || s.contains(char::is_whitespace)
            {
                return Err(bad(format!("invalid value {s:?}")));
            }
        }
        if let Some(d) = h.distance {
            if !(1..=255).contains(&d) {
                return Err(bad(format!("invalid distance {d} (must be 1-255)")));
            }
        }
    }
    Ok(())
}

/// The route's own VRF must exist when named ("default" arrives as null).
fn check_vrf(plat: &mut dyn Platform, vrf: Option<&str>) -> WriteResult {
    let Some(vrf) = vrf else { return Ok(()) };
    if vrf.is_empty() || vrf == "default" {
        return Err(bad("the default VRF is expressed as vrf: null"));
    }
    if vrf.contains('|') || vrf.contains(char::is_whitespace) {
        return Err(bad(format!("invalid VRF name {vrf:?}")));
    }
    if !plat.exists(CONFIG_DB, &format!("VRF|{vrf}")).map_err(WriteError::Redis)? {
        return Err(bad(format!("no such VRF {vrf}")));
    }
    Ok(())
}

/// Every CONFIG_DB key that could hold this (vrf, prefix) — the default VRF
/// has two spellings (`PREFIX` and `default|PREFIX`).
fn keys_for(vrf: Option<&str>, prefix: &str) -> Vec<String> {
    match vrf {
        Some(vrf) => vec![format!("STATIC_ROUTE|{vrf}|{prefix}")],
        None => vec![
            format!("STATIC_ROUTE|{prefix}"),
            format!("STATIC_ROUTE|default|{prefix}"),
        ],
    }
}

// ── PUT /api/routing/static-routes ──────────────────────────────────────────

/// Upsert: replace the whole STATIC_ROUTE row for (vrf, prefix).
pub fn put(plat: &mut dyn Platform, route: &RouteInput) -> WriteResult {
    let _lock = store::feature_lock("static-routes");
    require_supported(plat)?;
    check_route(plat, route)?;
    let keys = keys_for(route.vrf.as_deref(), &route.prefix);
    let fields = row_from_hops(&route.next_hops);
    let fields: Vec<(&str, &str)> = fields.iter().map(|(f, v)| (*f, v.as_str())).collect();
    store::apply(plat, |b| {
        // Full replace: stale fields (and the alternate default-VRF
        // spelling) must not survive the upsert.
        for key in &keys {
            b.del(CONFIG_DB, key)?;
        }
        b.hset(CONFIG_DB, &keys[0], &fields)
    })
    .map_err(WriteError::Redis)
}

// ── POST /api/routing/static-routes/delete ──────────────────────────────────

pub fn delete(plat: &mut dyn Platform, key: &RouteKey) -> WriteResult {
    let _lock = store::feature_lock("static-routes");
    require_supported(plat)?;
    check_prefix(&key.prefix).map_err(bad)?;
    let vrf = match key.vrf.as_deref() {
        Some("default") | Some("") | None => None,
        Some(vrf) => Some(vrf),
    };
    let mut found = false;
    for k in keys_for(vrf, &key.prefix) {
        if plat.exists(CONFIG_DB, &k).map_err(WriteError::Redis)? {
            found = true;
            plat.del(CONFIG_DB, &k).map_err(WriteError::Redis)?;
        }
    }
    if !found {
        let vrf = vrf.unwrap_or("the default VRF");
        return Err(WriteError::NotFound(format!(
            "no static route for {} in {vrf}",
            key.prefix
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::store::mem::MemPlatform;
    use super::*;

    fn platform() -> MemPlatform {
        let mut m = MemPlatform::new();
        m.seed(CONFIG_DB, "FEATURE|bgp", &[("state", "enabled")]);
        m.seed(CONFIG_DB, "VRF|VrfBlue", &[("fallback", "false")]);
        m
    }

    fn hop(gateway: Option<&str>, interface: Option<&str>) -> NextHop {
        NextHop {
            gateway: gateway.map(str::to_string),
            interface: interface.map(str::to_string),
            nexthop_vrf: None,
            blackhole: false,
            distance: None,
        }
    }

    #[test]
    fn decodes_parallel_fields() {
        let mut r = std::collections::HashMap::new();
        r.insert("nexthop".to_string(), "10.0.0.1,10.0.0.2".to_string());
        r.insert("ifname".to_string(), ",Ethernet0".to_string());
        r.insert("distance".to_string(), "0,20".to_string());
        r.insert("blackhole".to_string(), "false,false".to_string());
        let hops = hops_from_row(&r);
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(hops[0].interface, None);
        assert_eq!(hops[0].distance, None); // 0 = FRR default
        assert_eq!(hops[1].interface.as_deref(), Some("Ethernet0"));
        assert_eq!(hops[1].distance, Some(20));
        // Fields shorter than the hop count pad out with empties.
        r.remove("ifname");
        let hops = hops_from_row(&r);
        assert_eq!(hops[1].interface, None);
    }

    #[test]
    fn get_reads_both_key_spellings() {
        let mut m = platform();
        m.seed(CONFIG_DB, "STATIC_ROUTE|10.1.0.0/16", &[("nexthop", "10.0.0.1")]);
        m.seed(
            CONFIG_DB,
            "STATIC_ROUTE|default|10.2.0.0/16",
            &[("blackhole", "true")],
        );
        m.seed(
            CONFIG_DB,
            "STATIC_ROUTE|VrfBlue|10.3.0.0/16",
            &[("nexthop", "10.0.0.9"), ("nexthop-vrf", "default")],
        );
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], true);
        let routes = doc["routes"].as_array().unwrap();
        assert_eq!(routes.len(), 3);
        // Default-VRF routes (both spellings) come first with vrf null.
        assert_eq!(routes[0]["vrf"], serde_json::Value::Null);
        assert_eq!(routes[0]["prefix"], "10.1.0.0/16");
        assert_eq!(routes[1]["vrf"], serde_json::Value::Null);
        assert_eq!(routes[1]["next_hops"][0]["blackhole"], true);
        assert_eq!(routes[2]["vrf"], "VrfBlue");
        assert_eq!(routes[2]["next_hops"][0]["nexthop_vrf"], "default");
    }

    #[test]
    fn put_writes_aligned_fields() {
        let mut m = platform();
        put(
            &mut m,
            &RouteInput {
                vrf: None,
                prefix: "10.20.0.0/16".into(),
                next_hops: vec![
                    NextHop { distance: Some(10), ..hop(Some("10.0.0.1"), None) },
                    hop(None, Some("Ethernet0")),
                ],
            },
        )
        .unwrap();
        let r = m.row(CONFIG_DB, "STATIC_ROUTE|10.20.0.0/16");
        assert_eq!(r.get("nexthop").unwrap(), "10.0.0.1,");
        assert_eq!(r.get("ifname").unwrap(), ",Ethernet0");
        assert_eq!(r.get("distance").unwrap(), "10,0");
        assert_eq!(r.get("blackhole").unwrap(), "false,false");
        assert_eq!(r.get("nexthop-vrf").unwrap(), ",");
    }

    #[test]
    fn put_replaces_alternate_default_spelling() {
        let mut m = platform();
        m.seed(
            CONFIG_DB,
            "STATIC_ROUTE|default|10.20.0.0/16",
            &[("nexthop", "10.0.0.9"), ("distance", "50")],
        );
        put(
            &mut m,
            &RouteInput {
                vrf: None,
                prefix: "10.20.0.0/16".into(),
                next_hops: vec![hop(Some("10.0.0.1"), None)],
            },
        )
        .unwrap();
        assert!(!m.has_key(CONFIG_DB, "STATIC_ROUTE|default|10.20.0.0/16"));
        let r = m.row(CONFIG_DB, "STATIC_ROUTE|10.20.0.0/16");
        assert_eq!(r.get("nexthop").unwrap(), "10.0.0.1");
    }

    #[test]
    fn validation_rejects_bad_routes() {
        let mut m = platform();
        let cases: Vec<RouteInput> = vec![
            // No hops.
            RouteInput { vrf: None, prefix: "10.0.0.0/8".into(), next_hops: vec![] },
            // Bad prefix.
            RouteInput { vrf: None, prefix: "10.0.0.0".into(), next_hops: vec![hop(Some("10.0.0.1"), None)] },
            RouteInput { vrf: None, prefix: "10.0.0.0/33".into(), next_hops: vec![hop(Some("10.0.0.1"), None)] },
            // Unknown VRF.
            RouteInput { vrf: Some("VrfNope".into()), prefix: "10.0.0.0/8".into(), next_hops: vec![hop(Some("10.0.0.1"), None)] },
            // "default" must arrive as null.
            RouteInput { vrf: Some("default".into()), prefix: "10.0.0.0/8".into(), next_hops: vec![hop(Some("10.0.0.1"), None)] },
            // Empty hop.
            RouteInput { vrf: None, prefix: "10.0.0.0/8".into(), next_hops: vec![hop(None, None)] },
            // Bad gateway.
            RouteInput { vrf: None, prefix: "10.0.0.0/8".into(), next_hops: vec![hop(Some("not-an-ip"), None)] },
            // Blackhole + gateway.
            RouteInput {
                vrf: None,
                prefix: "10.0.0.0/8".into(),
                next_hops: vec![NextHop { blackhole: true, ..hop(Some("10.0.0.1"), None) }],
            },
            // Bad distance.
            RouteInput {
                vrf: None,
                prefix: "10.0.0.0/8".into(),
                next_hops: vec![NextHop { distance: Some(300), ..hop(Some("10.0.0.1"), None) }],
            },
        ];
        for route in cases {
            let err = put(&mut m, &route).unwrap_err();
            assert!(matches!(err, WriteError::BadRequest(_)), "{route:?}");
        }
        // Nothing was written by any of the rejected puts.
        assert!(m.log.iter().all(|l| !l.contains("STATIC_ROUTE")), "{:?}", m.log);
    }

    #[test]
    fn ipv6_and_vrf_routes() {
        let mut m = platform();
        put(
            &mut m,
            &RouteInput {
                vrf: Some("VrfBlue".into()),
                prefix: "fd00::/64".into(),
                next_hops: vec![hop(Some("fd00::1"), None)],
            },
        )
        .unwrap();
        assert!(m.has_key(CONFIG_DB, "STATIC_ROUTE|VrfBlue|fd00::/64"));
    }

    #[test]
    fn delete_removes_either_spelling() {
        let mut m = platform();
        m.seed(CONFIG_DB, "STATIC_ROUTE|default|10.1.0.0/16", &[("nexthop", "10.0.0.1")]);
        delete(&mut m, &RouteKey { vrf: None, prefix: "10.1.0.0/16".into() }).unwrap();
        assert!(!m.has_key(CONFIG_DB, "STATIC_ROUTE|default|10.1.0.0/16"));
        // Gone → 404.
        let err = delete(&mut m, &RouteKey { vrf: None, prefix: "10.1.0.0/16".into() }).unwrap_err();
        assert!(matches!(err, WriteError::NotFound(_)));
    }

    #[test]
    fn unsupported_without_bgp() {
        let mut m = MemPlatform::new();
        let doc = get(&mut m).unwrap();
        assert_eq!(doc["capability"]["supported"], false);
        let err = put(
            &mut m,
            &RouteInput {
                vrf: None,
                prefix: "10.0.0.0/8".into(),
                next_hops: vec![hop(Some("10.0.0.1"), None)],
            },
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Conflict(_)));
    }
}
