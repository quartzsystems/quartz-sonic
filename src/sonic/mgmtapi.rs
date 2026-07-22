//! The local management API the controller's ProxyRequests are routed to.
//!
//! Unlike QuartzFire (which fronts a separate local web UI over loopback
//! HTTP), quartz-sonic answers the console's `/api/…` calls inside the agent
//! itself: SONiC has no bundled management backend to proxy to, and keeping
//! the surface in-process means one less listener on the switch.
//!
//! Endpoints (mirroring the header comments in quartz-command's
//! frontend/lib/device/*.ts — the agent is the source of truth for shapes):
//!   GET    /api/system/info                    — SONiC version, platform, HWSKU, serial, …
//!   GET    /api/system/health                  — resource gauges + redis reachability
//!   POST   /api/system/reboot                  — graceful reboot via SONiC's `reboot` script
//!   GET    /api/switching/ports                — port inventory: status, VLANs, error counters
//!   PUT    /api/switching/ports/{name}         — patch port config + VLAN membership
//!   GET    /api/switching/port-channels        — LAGs with per-member state
//!   POST   /api/switching/port-channels        — create a LAG
//!   PUT    /api/switching/port-channels/{name} — converge a LAG's fields + members
//!   DELETE /api/switching/port-channels/{name} — remove a LAG
//!   GET    /api/switching/vlans                — VLANs with members and L3 config
//!   POST   /api/switching/vlans                — create a VLAN
//!   PUT    /api/switching/vlans/{id}           — converge a VLAN's fields + sets
//!   DELETE /api/switching/vlans/{id}           — remove a VLAN and its rows
//!
//! Configure → Switching feature pages (every GET leads with a `capability`
//! envelope { supported, read_only, reason } from the capability probe):
//!   GET    /api/switching/spanning-tree                — STP global/VLAN/port config + oper state
//!   PUT    /api/switching/spanning-tree/global         — mode (pvst/mst/disabled) + timers
//!   PUT    /api/switching/spanning-tree/vlans/{id}     — per-VLAN overrides (null = inherit)
//!   PUT    /api/switching/spanning-tree/ports/{name}   — per-port STP config
//!   GET    /api/switching/loop-protection              — BPDU/root guard per port
//!   PUT    /api/switching/loop-protection/ports/{name} — the three guard fields only
//!   POST   /api/switching/loop-protection/ports/{name}/recover — re-enable a guard-shut port
//!   GET    /api/switching/lldp                         — config + local chassis + neighbors
//!   PUT    /api/switching/lldp/config                  — enable/disable (+ timers on enterprise)
//!   GET    /api/switching/igmp-snooping                — per-VLAN snooping + groups (enterprise)
//!   PUT    /api/switching/igmp-snooping/vlans/{id}     — per-VLAN snooping config
//!
//! Configure → Routing:
//!   GET    /api/routing/l3-interfaces                  — all L3-capable interfaces
//!   POST   /api/routing/l3-interfaces                  — create a loopback
//!   PUT    /api/routing/l3-interfaces/{name}           — vrf + full IP set (rebind-sequenced)
//!   DELETE /api/routing/l3-interfaces/{name}           — loopbacks only
//!   GET    /api/routing/vrfs                           — VRFs + bound interfaces + mgmt VRF
//!   POST   /api/routing/vrfs                           — create a VRF (name ^Vrf…)
//!   PUT    /api/routing/vrfs/{name}                    — fallback/vni ("mgmt" is special, below)
//!   DELETE /api/routing/vrfs/{name}                    — refused while interfaces are bound
//!   PUT    /api/routing/vrfs/mgmt                      — toggle mgmt VRF via `config vrf …`
//!   GET    /api/routing/bgp                            — mode frrcfgd/legacy/unavailable
//!   PUT    /api/routing/bgp/globals/{vrf}              — instance (local_asn null = remove)
//!   POST   /api/routing/bgp/neighbors                  — create a neighbor
//!   PUT    /api/routing/bgp/neighbors/{vrf}/{peer}     — converge a neighbor (+ full AF set)
//!   DELETE /api/routing/bgp/neighbors/{vrf}/{peer}     — remove a neighbor
//!   GET    /api/routing/ospf                           — instances/areas/interfaces/neighbors
//!   PUT    /api/routing/ospf/instances/{vrf}           — enable/disable an instance
//!   PUT    /api/routing/ospf/instances/{vrf}/areas/{a} — stub + full network set
//!   DELETE /api/routing/ospf/instances/{vrf}/areas/{a} — remove an area
//!   PUT    /api/routing/ospf/interfaces/{name}         — per-interface OSPF (area null = out)
//!   GET    /api/routing/isis                           — instance/interfaces/adjacencies (vtysh)
//!   PUT    /api/routing/isis/instance                  — NET/level (net null = remove)
//!   PUT    /api/routing/isis/interfaces/{name}         — per-interface IS-IS
//!
//! CONFIG_DB writes are persisted with `config save -y` (best-effort);
//! IS-IS writes persist via `vtysh -c "write memory"` under the split
//! routing-config modes instead. Errors: non-2xx with {"error": …} — 400
//! invalid payloads, 404 unknown resources, 409 state conflicts (feature
//! unsupported on the image, resource in use), 422 well-formed values the
//! image can't take. Unknown paths get a 404-style ProxyResponse with
//! `error` set; a bad request must never crash the stream.

use serde_json::json;

use crate::sonic;
use crate::sonic::store::{Platform, SysPlatform};
use crate::sonic::switching::{self, WriteError};
use crate::sonic::{bgp, igmp, isis, l3, lldp, ospf, stp};

/// A ProxyResponse body-tuple: (http_status, content_type, body, error).
pub type CallResult = (u32, String, Vec<u8>, String);

const JSON: &str = "application/json";

pub struct Api {
    pub agent_version: String,
    pub device_id: String,
}

/// Routing decision, separated from execution for testability.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    SystemInfo,
    SystemHealth,
    SystemReboot,
    SwitchingPorts,
    PortUpdate(String),
    SwitchingPortChannels,
    PortChannelCreate,
    PortChannelUpdate(String),
    PortChannelDelete(String),
    SwitchingVlans,
    VlanCreate,
    VlanUpdate(u32),
    VlanDelete(u32),
    StpGet,
    StpGlobalPut,
    StpVlanPut(u32),
    StpPortPut(String),
    LoopGet,
    LoopPortPut(String),
    LoopRecover(String),
    LldpGet,
    LldpConfigPut,
    IgmpGet,
    IgmpVlanPut(u32),
    L3Get,
    L3Create,
    L3Put(String),
    L3Delete(String),
    VrfsGet,
    VrfCreate,
    VrfPut(String),
    VrfDelete(String),
    MgmtVrfPut,
    BgpGet,
    BgpGlobalPut(String),
    BgpNeighborCreate,
    BgpNeighborPut(String, String),
    BgpNeighborDelete(String, String),
    OspfGet,
    OspfInstancePut(String),
    OspfAreaPut(String, String),
    OspfAreaDelete(String, String),
    OspfInterfacePut(String),
    IsisGet,
    IsisInstancePut,
    IsisInterfacePut(String),
    NotFound,
    MethodNotAllowed { allowed: &'static str },
}

/// Match a method + path (query string ignored) to a route.
fn route(method: &str, path: &str) -> Route {
    let path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    match path {
        "/api/system/info" => match method {
            "GET" => Route::SystemInfo,
            _ => Route::MethodNotAllowed { allowed: "GET" },
        },
        "/api/system/health" => match method {
            "GET" => Route::SystemHealth,
            _ => Route::MethodNotAllowed { allowed: "GET" },
        },
        "/api/system/reboot" => match method {
            "POST" => Route::SystemReboot,
            _ => Route::MethodNotAllowed { allowed: "POST" },
        },
        "/api/switching/ports" => match method {
            "GET" => Route::SwitchingPorts,
            _ => Route::MethodNotAllowed { allowed: "GET" },
        },
        "/api/switching/port-channels" => match method {
            "GET" => Route::SwitchingPortChannels,
            "POST" => Route::PortChannelCreate,
            _ => Route::MethodNotAllowed { allowed: "GET, POST" },
        },
        "/api/switching/vlans" => match method {
            "GET" => Route::SwitchingVlans,
            "POST" => Route::VlanCreate,
            _ => Route::MethodNotAllowed { allowed: "GET, POST" },
        },
        _ => route_item(method, path),
    }
}

/// Routes with a trailing `{name}` / `{vlan_id}` path segment.
fn route_item(method: &str, path: &str) -> Route {
    if let Some(name) = item_name(path, "/api/switching/ports/") {
        return match method {
            "PUT" => Route::PortUpdate(name.to_string()),
            _ => Route::MethodNotAllowed { allowed: "PUT" },
        };
    }
    if let Some(name) = item_name(path, "/api/switching/port-channels/") {
        return match method {
            "PUT" => Route::PortChannelUpdate(name.to_string()),
            "DELETE" => Route::PortChannelDelete(name.to_string()),
            _ => Route::MethodNotAllowed { allowed: "PUT, DELETE" },
        };
    }
    if let Some(id) = item_name(path, "/api/switching/vlans/") {
        // A non-numeric id can't name a VLAN — 404, not 405.
        let Ok(id) = id.parse::<u32>() else { return Route::NotFound };
        return match method {
            "PUT" => Route::VlanUpdate(id),
            "DELETE" => Route::VlanDelete(id),
            _ => Route::MethodNotAllowed { allowed: "PUT, DELETE" },
        };
    }
    route_features(method, path)
}

/// The Configure → Switching / Routing feature trees, matched on path
/// segments (they nest deeper than the older prefix-style item routes).
fn route_features(method: &str, path: &str) -> Route {
    let segs: Vec<&str> =
        path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    // One method per arm keeps this readable; anything else on a known path
    // is a 405 with the allowed method.
    let need = |want: &'static str, r: Route| -> Route {
        if method == want {
            r
        } else {
            Route::MethodNotAllowed { allowed: want }
        }
    };
    match segs.as_slice() {
        ["api", "switching", "spanning-tree"] => need("GET", Route::StpGet),
        ["api", "switching", "spanning-tree", "global"] => need("PUT", Route::StpGlobalPut),
        ["api", "switching", "spanning-tree", "vlans", id] => match id.parse() {
            Ok(id) => need("PUT", Route::StpVlanPut(id)),
            Err(_) => Route::NotFound,
        },
        ["api", "switching", "spanning-tree", "ports", name] => {
            need("PUT", Route::StpPortPut(name.to_string()))
        }
        ["api", "switching", "loop-protection"] => need("GET", Route::LoopGet),
        ["api", "switching", "loop-protection", "ports", name] => {
            need("PUT", Route::LoopPortPut(name.to_string()))
        }
        ["api", "switching", "loop-protection", "ports", name, "recover"] => {
            need("POST", Route::LoopRecover(name.to_string()))
        }
        ["api", "switching", "lldp"] => need("GET", Route::LldpGet),
        ["api", "switching", "lldp", "config"] => need("PUT", Route::LldpConfigPut),
        ["api", "switching", "igmp-snooping"] => need("GET", Route::IgmpGet),
        ["api", "switching", "igmp-snooping", "vlans", id] => match id.parse() {
            Ok(id) => need("PUT", Route::IgmpVlanPut(id)),
            Err(_) => Route::NotFound,
        },
        ["api", "routing", "l3-interfaces"] => match method {
            "GET" => Route::L3Get,
            "POST" => Route::L3Create,
            _ => Route::MethodNotAllowed { allowed: "GET, POST" },
        },
        ["api", "routing", "l3-interfaces", name] => match method {
            "PUT" => Route::L3Put(name.to_string()),
            "DELETE" => Route::L3Delete(name.to_string()),
            _ => Route::MethodNotAllowed { allowed: "PUT, DELETE" },
        },
        ["api", "routing", "vrfs"] => match method {
            "GET" => Route::VrfsGet,
            "POST" => Route::VrfCreate,
            _ => Route::MethodNotAllowed { allowed: "GET, POST" },
        },
        // The management VRF is a toggle, not a Vrf… row — special-cased
        // ahead of the generic {name} arm.
        ["api", "routing", "vrfs", "mgmt"] => need("PUT", Route::MgmtVrfPut),
        ["api", "routing", "vrfs", name] => match method {
            "PUT" => Route::VrfPut(name.to_string()),
            "DELETE" => Route::VrfDelete(name.to_string()),
            _ => Route::MethodNotAllowed { allowed: "PUT, DELETE" },
        },
        ["api", "routing", "bgp"] => need("GET", Route::BgpGet),
        ["api", "routing", "bgp", "globals", vrf] => {
            need("PUT", Route::BgpGlobalPut(vrf.to_string()))
        }
        ["api", "routing", "bgp", "neighbors"] => need("POST", Route::BgpNeighborCreate),
        ["api", "routing", "bgp", "neighbors", vrf, peer] => match method {
            "PUT" => Route::BgpNeighborPut(vrf.to_string(), peer.to_string()),
            "DELETE" => Route::BgpNeighborDelete(vrf.to_string(), peer.to_string()),
            _ => Route::MethodNotAllowed { allowed: "PUT, DELETE" },
        },
        ["api", "routing", "ospf"] => need("GET", Route::OspfGet),
        ["api", "routing", "ospf", "instances", vrf] => {
            need("PUT", Route::OspfInstancePut(vrf.to_string()))
        }
        ["api", "routing", "ospf", "instances", vrf, "areas", area] => match method {
            "PUT" => Route::OspfAreaPut(vrf.to_string(), area.to_string()),
            "DELETE" => Route::OspfAreaDelete(vrf.to_string(), area.to_string()),
            _ => Route::MethodNotAllowed { allowed: "PUT, DELETE" },
        },
        ["api", "routing", "ospf", "interfaces", name] => {
            need("PUT", Route::OspfInterfacePut(name.to_string()))
        }
        ["api", "routing", "isis"] => need("GET", Route::IsisGet),
        ["api", "routing", "isis", "instance"] => need("PUT", Route::IsisInstancePut),
        ["api", "routing", "isis", "interfaces", name] => {
            need("PUT", Route::IsisInterfacePut(name.to_string()))
        }
        _ => Route::NotFound,
    }
}

/// The single path segment after `prefix`; None when absent, empty, or nested.
fn item_name<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.strip_prefix(prefix).filter(|s| !s.is_empty() && !s.contains('/'))
}

impl Api {
    pub fn new(agent_version: String, device_id: String) -> Self {
        Self { agent_version, device_id }
    }

    /// Serve one proxied call. Never panics; every outcome is a well-formed
    /// ProxyResponse tuple.
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        _content_type: &str,
        body: Vec<u8>,
    ) -> CallResult {
        match route(method, path) {
            Route::SystemInfo => {
                let agent_version = self.agent_version.clone();
                let device_id = self.device_id.clone();
                run_blocking(move || system_info(&agent_version, &device_id)).await
            }
            Route::SystemHealth => run_blocking(system_health).await,
            Route::SystemReboot => reboot(),
            Route::SwitchingPorts => run_blocking(switching_ports).await,
            Route::SwitchingPortChannels => run_blocking(switching_port_channels).await,
            Route::SwitchingVlans => run_blocking(switching_vlans).await,
            Route::PortUpdate(name) => {
                run_blocking(move || {
                    with_body(&body, |p: &switching::PortPatch| switching::update_port(&name, p))
                })
                .await
            }
            Route::VlanCreate => {
                run_blocking(move || {
                    with_body(&body, |c: &switching::VlanCreate| {
                        switching::create_vlan(c.vlan_id, &c.input)
                    })
                })
                .await
            }
            Route::VlanUpdate(id) => {
                run_blocking(move || {
                    with_body(&body, |i: &switching::VlanInput| switching::update_vlan(id, i))
                })
                .await
            }
            Route::VlanDelete(id) => {
                run_blocking(move || write_outcome(switching::delete_vlan(id))).await
            }
            Route::PortChannelCreate => {
                run_blocking(move || {
                    with_body(&body, |c: &switching::PortChannelCreate| {
                        switching::create_port_channel(&c.name, &c.input)
                    })
                })
                .await
            }
            Route::PortChannelUpdate(name) => {
                run_blocking(move || {
                    with_body(&body, |i: &switching::PortChannelInput| {
                        switching::update_port_channel(&name, i)
                    })
                })
                .await
            }
            Route::PortChannelDelete(name) => {
                run_blocking(move || write_outcome(switching::delete_port_channel(&name))).await
            }
            // ── Configure → Switching feature pages ─────────────────────────
            Route::StpGet => run_blocking(|| doc_get(stp::get)).await,
            Route::StpGlobalPut => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &stp::GlobalInput| {
                        stp::put_global(p, i)
                    })
                })
                .await
            }
            Route::StpVlanPut(id) => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &stp::VlanInput| {
                        stp::put_vlan(p, id, i)
                    })
                })
                .await
            }
            Route::StpPortPut(name) => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &stp::PortInput| {
                        stp::put_port(p, &name, i)
                    })
                })
                .await
            }
            Route::LoopGet => run_blocking(|| doc_get(stp::get_loop_protection)).await,
            Route::LoopPortPut(name) => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &stp::LoopPortInput| {
                        stp::put_loop_port(p, &name, i)
                    })
                })
                .await
            }
            Route::LoopRecover(name) => {
                run_blocking(move || platform_write(true, |p| stp::recover_port(p, &name))).await
            }
            Route::LldpGet => run_blocking(|| doc_get(lldp::get)).await,
            Route::LldpConfigPut => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &lldp::ConfigInput| {
                        lldp::put_config(p, i)
                    })
                })
                .await
            }
            Route::IgmpGet => run_blocking(|| doc_get(igmp::get)).await,
            Route::IgmpVlanPut(id) => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &igmp::VlanInput| {
                        igmp::put_vlan(p, id, i)
                    })
                })
                .await
            }
            // ── Configure → Routing ─────────────────────────────────────────
            Route::L3Get => run_blocking(|| doc_get(l3::get_interfaces)).await,
            Route::L3Create => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &l3::LoopbackCreate| {
                        l3::create_loopback(p, i)
                    })
                })
                .await
            }
            Route::L3Put(name) => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &l3::InterfaceInput| {
                        l3::put_interface(p, &name, i)
                    })
                })
                .await
            }
            Route::L3Delete(name) => {
                run_blocking(move || platform_write(true, |p| l3::delete_interface(p, &name)))
                    .await
            }
            Route::VrfsGet => run_blocking(|| doc_get(l3::get_vrfs)).await,
            Route::VrfCreate => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &l3::VrfCreate| l3::create_vrf(p, i))
                })
                .await
            }
            Route::VrfPut(name) => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &l3::VrfInput| {
                        l3::update_vrf(p, &name, i)
                    })
                })
                .await
            }
            Route::VrfDelete(name) => {
                run_blocking(move || platform_write(true, |p| l3::delete_vrf(p, &name))).await
            }
            // `config vrf add|del mgmt` persists on its own; no config save.
            Route::MgmtVrfPut => {
                run_blocking(move || {
                    with_platform_body(&body, false, |p, i: &l3::MgmtVrfInput| {
                        l3::put_mgmt_vrf(p, i)
                    })
                })
                .await
            }
            Route::BgpGet => run_blocking(|| doc_get(bgp::get)).await,
            Route::BgpGlobalPut(vrf) => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &bgp::GlobalInput| {
                        bgp::put_global(p, &vrf, i)
                    })
                })
                .await
            }
            Route::BgpNeighborCreate => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &bgp::NeighborCreate| {
                        bgp::create_neighbor(p, i)
                    })
                })
                .await
            }
            Route::BgpNeighborPut(vrf, peer) => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &bgp::NeighborInput| {
                        bgp::put_neighbor(p, &vrf, &peer, i)
                    })
                })
                .await
            }
            Route::BgpNeighborDelete(vrf, peer) => {
                run_blocking(move || {
                    platform_write(true, |p| bgp::delete_neighbor(p, &vrf, &peer))
                })
                .await
            }
            Route::OspfGet => run_blocking(|| doc_get(ospf::get)).await,
            Route::OspfInstancePut(vrf) => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &ospf::InstanceInput| {
                        ospf::put_instance(p, &vrf, i)
                    })
                })
                .await
            }
            Route::OspfAreaPut(vrf, area) => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &ospf::AreaInput| {
                        ospf::put_area(p, &vrf, &area, i)
                    })
                })
                .await
            }
            Route::OspfAreaDelete(vrf, area) => {
                run_blocking(move || {
                    platform_write(true, |p| ospf::delete_area(p, &vrf, &area))
                })
                .await
            }
            Route::OspfInterfacePut(name) => {
                run_blocking(move || {
                    with_platform_body(&body, true, |p, i: &ospf::OspfInterfaceInput| {
                        ospf::put_interface(p, &name, i)
                    })
                })
                .await
            }
            Route::IsisGet => run_blocking(|| doc_get(isis::get)).await,
            // IS-IS lives in FRR, not CONFIG_DB — the module runs
            // `vtysh -c "write memory"` itself per the routing-config mode.
            Route::IsisInstancePut => {
                run_blocking(move || {
                    with_platform_body(&body, false, |p, i: &isis::InstanceInput| {
                        isis::put_instance(p, i)
                    })
                })
                .await
            }
            Route::IsisInterfacePut(name) => {
                run_blocking(move || {
                    with_platform_body(&body, false, |p, i: &isis::InterfaceInput| {
                        isis::put_interface(p, &name, i)
                    })
                })
                .await
            }
            Route::NotFound => (
                404,
                JSON.to_string(),
                json_body(&json!({ "error": "not found" })),
                format!("no such endpoint: {method} {path}"),
            ),
            Route::MethodNotAllowed { allowed } => (
                405,
                JSON.to_string(),
                json_body(&json!({ "error": "method not allowed", "allowed": allowed })),
                format!("method {method} not allowed on {path} (use {allowed})"),
            ),
        }
    }
}

/// Collectors read /proc and redis — off the async runtime they go.
async fn run_blocking(f: impl FnOnce() -> CallResult + Send + 'static) -> CallResult {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) => (
            0,
            String::new(),
            Vec::new(),
            format!("local handler panicked or was cancelled: {e}"),
        ),
    }
}

fn json_body(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

fn system_info(agent_version: &str, device_id: &str) -> CallResult {
    let facts = sonic::system_facts();
    let stats = super::stats::collect();
    // The console types these as string|null — an undetermined fact must
    // arrive as null, not "".
    let opt = |s: String| if s.is_empty() { serde_json::Value::Null } else { s.into() };
    let body = json!({
        "device_id": device_id,
        "hostname": facts.hostname,
        "sonic_version": opt(facts.sonic_version),
        "platform": opt(facts.platform),
        "hwsku": opt(facts.hwsku),
        "serial": opt(facts.serial),
        "uptime_secs": stats.uptime_secs,
        "agent_version": agent_version,
    });
    (200, JSON.to_string(), json_body(&body), String::new())
}

fn system_health() -> CallResult {
    let redis_ok = sonic::redis_ok();
    let stats = super::stats::collect();
    let body = json!({
        "status": if redis_ok { "ok" } else { "degraded" },
        "redis": redis_ok,
        "cpu_pct": stats.cpu_pct,
        "mem_pct": stats.mem_pct,
        "disk_pct": stats.disk_pct,
        "mem_used_bytes": stats.mem_used_bytes,
        "mem_total_bytes": stats.mem_total_bytes,
        "disk_used_bytes": stats.disk_used_bytes,
        "disk_total_bytes": stats.disk_total_bytes,
        "uptime_secs": stats.uptime_secs,
    });
    (200, JSON.to_string(), json_body(&body), String::new())
}

fn switching_ports() -> CallResult {
    match sonic::switching::ports() {
        Ok(ports) => (200, JSON.to_string(), json_body(&json!({ "ports": ports })), String::new()),
        Err(e) => redis_unreachable(&e),
    }
}

fn switching_port_channels() -> CallResult {
    match sonic::switching::port_channels() {
        Ok(pcs) => (
            200,
            JSON.to_string(),
            json_body(&json!({ "port_channels": pcs })),
            String::new(),
        ),
        Err(e) => redis_unreachable(&e),
    }
}

fn switching_vlans() -> CallResult {
    match sonic::switching::vlans() {
        Ok(vlans) => (200, JSON.to_string(), json_body(&json!({ "vlans": vlans })), String::new()),
        Err(e) => redis_unreachable(&e),
    }
}

/// CONFIG_DB itself was unreachable — the one condition the switching
/// endpoints are allowed to fail on (anything less degrades to the contract's
/// nulls/defaults inside the collectors).
fn redis_unreachable(e: &anyhow::Error) -> CallResult {
    let msg = format!("SONiC redis unreachable: {e:#}");
    (500, JSON.to_string(), json_body(&json!({ "error": msg })), msg)
}

/// Parse a write body and hand it to `op`; an unparsable body is a 400
/// before redis is ever touched.
fn with_body<T, F>(body: &[u8], op: F) -> CallResult
where
    T: serde::de::DeserializeOwned,
    F: FnOnce(&T) -> Result<(), WriteError>,
{
    match switching::parse_json::<T>(body) {
        Ok(v) => write_outcome(op(&v)),
        Err(msg) => error_response(400, msg),
    }
}

/// Serve a feature GET: assemble the document against the live platform.
fn doc_get(f: fn(&mut dyn Platform) -> anyhow::Result<serde_json::Value>) -> CallResult {
    let mut plat = SysPlatform::new();
    match f(&mut plat) {
        Ok(doc) => (200, JSON.to_string(), json_body(&doc), String::new()),
        Err(e) => redis_unreachable(&e),
    }
}

/// Parse a write body and run `op` against the live platform. `persist`
/// gates the trailing `config save -y` (off for pure-vtysh / CLI-managed
/// writes).
fn with_platform_body<T, F>(body: &[u8], persist: bool, op: F) -> CallResult
where
    T: serde::de::DeserializeOwned,
    F: FnOnce(&mut dyn Platform, &T) -> Result<(), WriteError>,
{
    match switching::parse_json::<T>(body) {
        Ok(v) => {
            let mut plat = SysPlatform::new();
            write_outcome_with(op(&mut plat, &v), persist)
        }
        Err(msg) => error_response(400, msg),
    }
}

/// A body-less platform write (recover / DELETE routes).
fn platform_write(
    persist: bool,
    op: impl FnOnce(&mut dyn Platform) -> Result<(), WriteError>,
) -> CallResult {
    let mut plat = SysPlatform::new();
    write_outcome_with(op(&mut plat), persist)
}

/// Map a write op's outcome to the contract: 200 {"ok": true} (after a
/// best-effort `config save -y`), 400/404/409/422/500 with {"error": …}, or
/// the readers' 500 shape when redis itself failed.
fn write_outcome(r: Result<(), WriteError>) -> CallResult {
    write_outcome_with(r, true)
}

fn write_outcome_with(r: Result<(), WriteError>, persist: bool) -> CallResult {
    match r {
        Ok(()) => {
            if persist {
                persist_config();
            }
            (200, JSON.to_string(), json_body(&json!({ "ok": true })), String::new())
        }
        Err(WriteError::BadRequest(msg)) => error_response(400, msg),
        Err(WriteError::NotFound(msg)) => error_response(404, msg),
        Err(WriteError::Conflict(msg)) => error_response(409, msg),
        Err(WriteError::Unprocessable(msg)) => error_response(422, msg),
        Err(WriteError::Internal(msg)) => error_response(500, msg),
        Err(WriteError::Redis(e)) => redis_unreachable(&e),
    }
}

fn error_response(status: u32, msg: String) -> CallResult {
    (status, JSON.to_string(), json_body(&json!({ "error": msg })), msg)
}

/// Persist CONFIG_DB to /etc/sonic/config_db.json so the mutation survives a
/// reboot. Best-effort: the write already applied, so a failed save is logged
/// (and the next successful one will pick it up), never surfaced as an error.
fn persist_config() {
    match std::process::Command::new("config").args(["save", "-y"]).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => tracing::warn!(
            "config save -y failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => tracing::warn!("config save -y could not run: {e}"),
    }
}

/// Kick off SONiC's graceful `reboot` script (falls back to /sbin/reboot),
/// detached and delayed a few seconds so the 202 response reaches the
/// controller before the box goes down.
fn reboot() -> CallResult {
    tracing::warn!("reboot requested by the controller");
    let spawned = std::process::Command::new("sh")
        .args(["-c", "sleep 3; reboot || /sbin/reboot"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    match spawned {
        Ok(_) => (
            202,
            JSON.to_string(),
            json_body(&json!({ "status": "rebooting" })),
            String::new(),
        ),
        Err(e) => (
            500,
            JSON.to_string(),
            json_body(&json!({ "error": format!("failed to start reboot: {e}") })),
            format!("failed to start reboot: {e}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_known_endpoints() {
        assert_eq!(route("GET", "/api/system/info"), Route::SystemInfo);
        assert_eq!(route("GET", "/api/system/health"), Route::SystemHealth);
        assert_eq!(route("POST", "/api/system/reboot"), Route::SystemReboot);
        // Query strings and trailing slashes don't change the route.
        assert_eq!(route("GET", "/api/system/info?verbose=1"), Route::SystemInfo);
        assert_eq!(route("GET", "/api/system/info/"), Route::SystemInfo);
    }

    #[test]
    fn routes_switching_endpoints() {
        assert_eq!(route("GET", "/api/switching/ports"), Route::SwitchingPorts);
        assert_eq!(
            route("GET", "/api/switching/port-channels"),
            Route::SwitchingPortChannels
        );
        assert_eq!(route("GET", "/api/switching/vlans"), Route::SwitchingVlans);
    }

    #[test]
    fn collection_paths_share_get_and_post() {
        assert_eq!(route("POST", "/api/switching/vlans"), Route::VlanCreate);
        assert_eq!(route("POST", "/api/switching/port-channels"), Route::PortChannelCreate);
        assert_eq!(
            route("DELETE", "/api/switching/vlans"),
            Route::MethodNotAllowed { allowed: "GET, POST" }
        );
        // Ports has no create — the collection stays GET-only.
        assert_eq!(
            route("POST", "/api/switching/ports"),
            Route::MethodNotAllowed { allowed: "GET" }
        );
    }

    #[test]
    fn routes_item_write_endpoints() {
        assert_eq!(
            route("PUT", "/api/switching/ports/Ethernet0"),
            Route::PortUpdate("Ethernet0".into())
        );
        assert_eq!(
            route("GET", "/api/switching/ports/Ethernet0"),
            Route::MethodNotAllowed { allowed: "PUT" }
        );
        assert_eq!(route("PUT", "/api/switching/vlans/10"), Route::VlanUpdate(10));
        assert_eq!(route("DELETE", "/api/switching/vlans/10"), Route::VlanDelete(10));
        assert_eq!(
            route("POST", "/api/switching/vlans/10"),
            Route::MethodNotAllowed { allowed: "PUT, DELETE" }
        );
        assert_eq!(
            route("PUT", "/api/switching/port-channels/PortChannel0001"),
            Route::PortChannelUpdate("PortChannel0001".into())
        );
        assert_eq!(
            route("DELETE", "/api/switching/port-channels/PortChannel0001"),
            Route::PortChannelDelete("PortChannel0001".into())
        );
        // Query strings and trailing slashes don't change item routes either.
        assert_eq!(
            route("PUT", "/api/switching/ports/Ethernet0/?dry=1"),
            Route::PortUpdate("Ethernet0".into())
        );
    }

    #[test]
    fn routes_switching_feature_endpoints() {
        assert_eq!(route("GET", "/api/switching/spanning-tree"), Route::StpGet);
        assert_eq!(route("PUT", "/api/switching/spanning-tree/global"), Route::StpGlobalPut);
        assert_eq!(route("PUT", "/api/switching/spanning-tree/vlans/10"), Route::StpVlanPut(10));
        assert_eq!(route("PUT", "/api/switching/spanning-tree/vlans/abc"), Route::NotFound);
        assert_eq!(
            route("PUT", "/api/switching/spanning-tree/ports/Ethernet0"),
            Route::StpPortPut("Ethernet0".into())
        );
        assert_eq!(route("GET", "/api/switching/loop-protection"), Route::LoopGet);
        assert_eq!(
            route("PUT", "/api/switching/loop-protection/ports/Ethernet0"),
            Route::LoopPortPut("Ethernet0".into())
        );
        assert_eq!(
            route("POST", "/api/switching/loop-protection/ports/Ethernet0/recover"),
            Route::LoopRecover("Ethernet0".into())
        );
        assert_eq!(route("GET", "/api/switching/lldp"), Route::LldpGet);
        assert_eq!(route("PUT", "/api/switching/lldp/config"), Route::LldpConfigPut);
        assert_eq!(route("GET", "/api/switching/igmp-snooping"), Route::IgmpGet);
        assert_eq!(
            route("PUT", "/api/switching/igmp-snooping/vlans/20"),
            Route::IgmpVlanPut(20)
        );
        // Wrong methods on feature paths are 405s, not 404s.
        assert_eq!(
            route("POST", "/api/switching/spanning-tree"),
            Route::MethodNotAllowed { allowed: "GET" }
        );
        assert_eq!(
            route("GET", "/api/switching/lldp/config"),
            Route::MethodNotAllowed { allowed: "PUT" }
        );
    }

    #[test]
    fn routes_routing_endpoints() {
        assert_eq!(route("GET", "/api/routing/l3-interfaces"), Route::L3Get);
        assert_eq!(route("POST", "/api/routing/l3-interfaces"), Route::L3Create);
        assert_eq!(
            route("PUT", "/api/routing/l3-interfaces/Ethernet0"),
            Route::L3Put("Ethernet0".into())
        );
        assert_eq!(
            route("DELETE", "/api/routing/l3-interfaces/Loopback0"),
            Route::L3Delete("Loopback0".into())
        );
        assert_eq!(route("GET", "/api/routing/vrfs"), Route::VrfsGet);
        assert_eq!(route("POST", "/api/routing/vrfs"), Route::VrfCreate);
        // "mgmt" is the toggle, every other name the generic item route.
        assert_eq!(route("PUT", "/api/routing/vrfs/mgmt"), Route::MgmtVrfPut);
        assert_eq!(route("PUT", "/api/routing/vrfs/VrfBlue"), Route::VrfPut("VrfBlue".into()));
        assert_eq!(
            route("DELETE", "/api/routing/vrfs/VrfBlue"),
            Route::VrfDelete("VrfBlue".into())
        );
        assert_eq!(route("GET", "/api/routing/bgp"), Route::BgpGet);
        assert_eq!(
            route("PUT", "/api/routing/bgp/globals/default"),
            Route::BgpGlobalPut("default".into())
        );
        assert_eq!(route("POST", "/api/routing/bgp/neighbors"), Route::BgpNeighborCreate);
        assert_eq!(
            route("PUT", "/api/routing/bgp/neighbors/default/10.0.0.1"),
            Route::BgpNeighborPut("default".into(), "10.0.0.1".into())
        );
        // IPv6 peers ride the path fine.
        assert_eq!(
            route("DELETE", "/api/routing/bgp/neighbors/VrfBlue/fc00::2"),
            Route::BgpNeighborDelete("VrfBlue".into(), "fc00::2".into())
        );
        assert_eq!(route("GET", "/api/routing/ospf"), Route::OspfGet);
        assert_eq!(
            route("PUT", "/api/routing/ospf/instances/default"),
            Route::OspfInstancePut("default".into())
        );
        assert_eq!(
            route("PUT", "/api/routing/ospf/instances/default/areas/0.0.0.0"),
            Route::OspfAreaPut("default".into(), "0.0.0.0".into())
        );
        assert_eq!(
            route("DELETE", "/api/routing/ospf/instances/VrfBlue/areas/1"),
            Route::OspfAreaDelete("VrfBlue".into(), "1".into())
        );
        assert_eq!(
            route("PUT", "/api/routing/ospf/interfaces/Ethernet0"),
            Route::OspfInterfacePut("Ethernet0".into())
        );
        assert_eq!(route("GET", "/api/routing/isis"), Route::IsisGet);
        assert_eq!(route("PUT", "/api/routing/isis/instance"), Route::IsisInstancePut);
        assert_eq!(
            route("PUT", "/api/routing/isis/interfaces/Ethernet0"),
            Route::IsisInterfacePut("Ethernet0".into())
        );
        assert_eq!(
            route("GET", "/api/routing/isis/instance"),
            Route::MethodNotAllowed { allowed: "PUT" }
        );
        assert_eq!(route("PUT", "/api/routing/nope"), Route::NotFound);
    }

    /// Feature write bodies parse before any platform access, so bad
    /// payloads 400 deterministically with no redis around.
    #[tokio::test]
    async fn unparsable_feature_write_bodies_yield_400() {
        let api = Api::new("test".into(), "QS-TEST".into());
        for (method, path, body) in [
            ("PUT", "/api/switching/spanning-tree/global", &b"{not json"[..]),
            ("PUT", "/api/switching/spanning-tree/global", br#"{"mode":"sideways"}"#),
            ("PUT", "/api/switching/lldp/config", br#"{"enabled":"maybe"}"#),
            ("PUT", "/api/routing/l3-interfaces/Ethernet0", br#"{"vrf":42}"#),
            ("POST", "/api/routing/bgp/neighbors", br#"{"vrf":"default"}"#),
            ("PUT", "/api/routing/isis/instance", br#"{"net":null,"level":"level-9"}"#),
        ] {
            let (status, _, body_out, error) =
                api.call(method, path, JSON, body.to_vec()).await;
            assert_eq!(status, 400, "{method} {path}: {error}");
            let v: serde_json::Value = serde_json::from_slice(&body_out).unwrap();
            assert!(v["error"].as_str().unwrap().starts_with("invalid body:"), "{v}");
        }
    }

    #[test]
    fn malformed_item_paths_are_not_found() {
        // A non-numeric VLAN id can't name a VLAN.
        assert_eq!(route("PUT", "/api/switching/vlans/abc"), Route::NotFound);
        assert_eq!(route("PUT", "/api/switching/vlans/-1"), Route::NotFound);
        // Nested segments aren't item names.
        assert_eq!(route("PUT", "/api/switching/ports/a/b"), Route::NotFound);
    }

    #[test]
    fn wrong_method_is_405_not_404() {
        assert_eq!(
            route("POST", "/api/system/info"),
            Route::MethodNotAllowed { allowed: "GET" }
        );
        assert_eq!(
            route("GET", "/api/system/reboot"),
            Route::MethodNotAllowed { allowed: "POST" }
        );
    }

    #[test]
    fn unknown_paths_fall_through_to_not_found() {
        assert_eq!(route("GET", "/api/nope"), Route::NotFound);
        assert_eq!(route("GET", "/etc/passwd"), Route::NotFound);
        assert_eq!(route("DELETE", "/"), Route::NotFound);
        assert_eq!(route("GET", ""), Route::NotFound);
    }

    /// The full call path for an unknown endpoint: 404, JSON body, error set,
    /// and — critically — no panic.
    #[tokio::test]
    async fn unknown_endpoint_yields_404_with_error() {
        let api = Api::new("test".into(), "QS-TEST".into());
        let (status, ct, body, error) = api.call("GET", "/api/does/not/exist", "", vec![]).await;
        assert_eq!(status, 404);
        assert_eq!(ct, "application/json");
        assert!(!error.is_empty());
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "not found");
    }

    #[tokio::test]
    async fn wrong_method_yields_405_with_error() {
        let api = Api::new("test".into(), "QS-TEST".into());
        let (status, _, _, error) = api.call("DELETE", "/api/system/reboot", "", vec![]).await;
        assert_eq!(status, 405);
        assert!(error.contains("use POST"), "{error}");
    }

    /// Body parsing happens before any redis access, so a bad payload is a
    /// deterministic 400 regardless of the environment.
    #[tokio::test]
    async fn unparsable_write_bodies_yield_400() {
        let api = Api::new("test".into(), "QS-TEST".into());
        for (method, path, body) in [
            ("PUT", "/api/switching/ports/Ethernet0", &b"{not json"[..]),
            ("PUT", "/api/switching/ports/Ethernet0", br#"{"admin_status":"sideways"}"#),
            ("POST", "/api/switching/vlans", br#"{"description":"missing vlan_id"}"#),
            ("POST", "/api/switching/port-channels", br#"{"name":"PortChannel1"}"#),
            ("PUT", "/api/switching/port-channels/PortChannel1", br#"{"protocol":"pagp"}"#),
        ] {
            let (status, ct, body, error) =
                api.call(method, path, "application/json", body.to_vec()).await;
            assert_eq!(status, 400, "{method} {path}: {error}");
            assert_eq!(ct, "application/json");
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(v["error"].as_str().unwrap().starts_with("invalid body:"), "{v}");
            assert!(!error.is_empty());
        }
    }

    /// Pure payload validation also precedes redis: an out-of-range VLAN id
    /// or a bad LAG name is a 400 even with no CONFIG_DB around.
    #[tokio::test]
    async fn invalid_payload_values_yield_400() {
        let api = Api::new("test".into(), "QS-TEST".into());
        let (status, _, body, _) = api
            .call("POST", "/api/switching/vlans", JSON, br#"{"vlan_id": 4095}"#.to_vec())
            .await;
        assert_eq!(status, 400);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"].as_str().unwrap().contains("invalid VLAN id"), "{v}");

        let pc = br#"{"name":"Po1","protocol":"lacp","admin_status":"up",
                      "fallback":false,"fast_rate":false,"members":[]}"#;
        let (status, _, body, _) =
            api.call("POST", "/api/switching/port-channels", JSON, pc.to_vec()).await;
        assert_eq!(status, 400);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"].as_str().unwrap().contains("invalid port channel name"), "{v}");

        let patch = br#"{"vlan_mode":"access","untagged_vlan":null}"#;
        let (status, _, body, _) = api
            .call("PUT", "/api/switching/ports/Ethernet0", JSON, patch.to_vec())
            .await;
        assert_eq!(status, 400);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"].as_str().unwrap().contains("requires untagged_vlan"), "{v}");
    }
}
