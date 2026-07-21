#!/bin/sh
# Build the quartz-sonic .deb (run on Linux or under WSL).
#
# A static musl binary makes one package run on community SONiC and
# Enterprise SONiC regardless of the underlying Debian base. ring's build
# script needs a C cross-compiler for musl: apt install musl-tools.
#
#   arm64 follow-up: rustup target add aarch64-unknown-linux-musl and
#   install gcc-aarch64-linux-gnu + musl cross toolchain, then re-run with
#   TARGET=aarch64-unknown-linux-musl.
set -eu

# Always build from the repo root, wherever the script is invoked from.
cd "$(dirname "$0")/.."

TARGET="${TARGET:-x86_64-unknown-linux-musl}"

rustup target add "$TARGET"
command -v cargo-deb >/dev/null 2>&1 || cargo install cargo-deb

cargo build --release --target "$TARGET"
# cargo-deb resolves the asset path against the --target dir automatically.
cargo deb --target "$TARGET" --no-build

echo
echo "package: $(ls -1 target/"$TARGET"/debian/quartz-sonic_*.deb | tail -n1)"
