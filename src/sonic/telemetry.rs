//! Periodic security-service telemetry.
//!
//! The SecurityTelemetry message is a fleet-wide contract whose four service
//! blocks (IPS, app control, geolocation, content filtering) describe
//! firewall subsystems a switch does not have. The proto requires all four
//! blocks to be present, so every snapshot reports `enabled = false` with
//! zero counters for each — the console then renders the services as "not
//! installed" rather than erroring on a missing block.

use std::time::Duration;

use crate::proto::device::{
    AppControlCounters, ContentFilterCounters, GeoCounters, IpsCounters, SecurityTelemetry,
};

/// How often the control channel emits a snapshot.
pub const INTERVAL: Duration = Duration::from_secs(60);

/// Collect a snapshot: all services absent on a switch.
pub fn collect() -> SecurityTelemetry {
    SecurityTelemetry {
        time_unix: crate::state::now_unix(),
        interval_secs: INTERVAL.as_secs() as u32,
        ips: Some(IpsCounters::default()),
        app_control: Some(AppControlCounters::default()),
        geolocation: Some(GeoCounters::default()),
        content_filtering: Some(ContentFilterCounters::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract: all four blocks present, all disabled, all counters zero.
    #[test]
    fn all_blocks_present_disabled_and_zero() {
        let t = collect();
        assert_eq!(t.interval_secs, 60);
        assert!(t.time_unix > 0);

        let ips = t.ips.expect("ips block present");
        assert!(!ips.enabled);
        assert_eq!((ips.prevented, ips.detected, ips.scans), (0, 0, 0));
        assert!(!ips.scans_available);

        let ac = t.app_control.expect("app_control block present");
        assert!(!ac.enabled);
        assert_eq!((ac.blocked, ac.detected, ac.total_requests), (0, 0, 0));

        let geo = t.geolocation.expect("geolocation block present");
        assert!(!geo.enabled);
        assert_eq!((geo.blocked, geo.connections, u64::from(geo.countries_blocked)), (0, 0, 0));

        let cf = t.content_filtering.expect("content_filtering block present");
        assert!(!cf.enabled);
        assert_eq!((cf.blocked, cf.allowed, cf.total_requests), (0, 0, 0));
    }

    /// Compile-time guard for the wrapping `control.rs` uses.
    #[test]
    fn snapshot_wraps_into_a_device_message() {
        use crate::proto::device::{device_message, DeviceMessage};
        let msg = DeviceMessage {
            msg: Some(device_message::Msg::SecurityTelemetry(collect())),
        };
        assert!(matches!(msg.msg, Some(device_message::Msg::SecurityTelemetry(_))));
    }
}
