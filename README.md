# quartz-sonic

Quartz Command fleet-management agent for SONiC switches — the SONiC
counterpart to the QuartzFire firewall agent. It enrolls a switch into
[Quartz Command](https://github.com/zagdrath/quartz-command) and maintains a
persistent mTLS control channel so the console can monitor and manage the
switch. Ships as a single static `.deb` that installs on both community SONiC
and Enterprise SONiC.

## Installing / updating

One-liner, on the switch (amd64):

```
curl -fsSL https://raw.githubusercontent.com/zagdrath/quartz-sonic/main/scripts/install.sh | sudo sh
```

The same command **updates** an installed agent: the script always fetches
the latest release, `dpkg -i` upgrades in place, and the package restarts
`quartz-sonic.service` after the upgrade — enrollment state and identity in
`/var/lib/quartz-sonic/` are untouched, so the switch reconnects as itself.
(To skip the script, the package itself is at
`https://github.com/zagdrath/quartz-sonic/releases/latest/download/quartz-sonic_amd64.deb`.)

## Enrolling a switch

Generate an enrollment token in the Quartz Command console, then on the
switch:

```
sudo quartz-sonic enroll '<TOKEN>'
```

The token pins the controller's issuing device CA by SHA-256 fingerprint, so
no public PKI trust is involved. Enrollment generates the device's Ed25519
identity on first run (`/var/lib/quartz-sonic/`, root-only), proves key
possession, and receives the mTLS client certificate the daemon then uses.
The device ID is derived from the public key
(`QS-XXXX-XXXX-XXXX-XXXX`) and shown by:

```
quartz-sonic status
```

An adopted device cannot re-enroll until it is revoked in the console.

## What the daemon does

`quartz-sonic.service` (installed enabled, `Restart=always`) connects to the
assigned gateway with mTLS and holds the `ControlStream` open:

* answers the console's proxied `/api/…` calls — currently
  `GET /api/system/info` (SONiC version, platform, HWSKU, serial),
  `GET /api/system/health`, `POST /api/system/reboot`, and the
  Configure → Switching pages' `GET /api/switching/ports`,
  `GET /api/switching/port-channels`, and `GET /api/switching/vlans` —
  backed by CONFIG_DB/STATE_DB/COUNTERS_DB and the platform CLIs;
* pushes `DeviceStats` every ~30 s (CPU/mem/disk gauges plus true byte
  figures, uptime, best-effort public IP, and the top ~8 interfaces by
  traffic from COUNTERS_DB);
* pushes `SecurityTelemetry` every ~60 s (all service blocks reported
  absent — switches have no IPS/app-control/geo/content-filter);
* renews its client certificate at 2/3 of cert lifetime and reconnects with
  jittered exponential backoff whenever the stream drops.

Logs go to journald: `journalctl -u quartz-sonic`.

## Layout on the switch

| path                        | content                                  |
|-----------------------------|------------------------------------------|
| `/usr/bin/quartz-sonic`     | single binary: `enroll`, `status`, `run` |
| `/var/lib/quartz-sonic/`    | identity, certificates, state (0700)     |
| `/etc/quartz-sonic/`        | reserved for config (none needed yet)    |
| `/run/quartz-sonic/status.json` | live status for `quartz-sonic status` |

## Building the package

On Linux (or WSL), with `musl-tools` installed:

```
./scripts/build-deb.sh
```

produces `target/x86_64-unknown-linux-musl/debian/quartz-sonic_<ver>_amd64.deb`
— a static musl build, so the one package runs across the Debian bases the
SONiC images use. (arm64 is a follow-up: `TARGET=aarch64-unknown-linux-musl
./build-deb.sh` with a musl cross toolchain.)

Development builds and the test suite run on any host (no protoc needed —
protos compile with protox):

```
cargo test
```

CI (`.github/workflows/build-deb.yml`) tests and packages on every push and
uploads the `.deb` as an artifact.

## Versioning & releasing

The `VERSION` file at the repo root is the single source of truth. build.rs
bakes it into the binary and fails the build if Cargo.toml's `[package]`
version drifts from it (cargo-deb stamps the package from Cargo.toml, so the
two must agree). To release:

1. Bump `VERSION` and the `version` in `Cargo.toml` to match.
2. Tag and push: `git tag v$(cat VERSION) && git push --tags`.

CI verifies the tag matches `VERSION`, then publishes the GitHub release with
the versioned `.deb` plus the stable-named `quartz-sonic_amd64.deb` the
install one-liner fetches.

## Protocol

The gRPC contract lives in `proto/quartzcommand/…` and is copied verbatim
from quartz-command (`backend/proto/…`). Do not edit it here; it is shared
fleet-wide. The `qf_version` fields are likewise fleet-wide: quartz-sonic
reports its own agent version in them.
