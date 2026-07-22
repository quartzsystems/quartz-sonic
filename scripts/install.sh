#!/bin/sh
# quartz-sonic installer/updater for SONiC switches.
#
#   curl -fsSL https://raw.githubusercontent.com/quartzsystems/quartz-sonic/main/scripts/install.sh | sudo sh
#
# Fetches the latest released .deb and installs it with dpkg. Running it on a
# box that already has quartz-sonic upgrades in place: enrollment state and
# identity in /var/lib/quartz-sonic/ are untouched and the service restarts
# after the upgrade, so the switch reconnects as itself.
set -eu

REPO="quartzsystems/quartz-sonic"

if [ "$(id -u)" -ne 0 ]; then
    echo "quartz-sonic install: must run as root — pipe to 'sudo sh'" >&2
    exit 1
fi

# amd64 is the published architecture today; arm64 is a planned follow-up.
arch="$(dpkg --print-architecture 2>/dev/null || uname -m)"
case "$arch" in
    amd64|x86_64) deb="quartz-sonic_amd64.deb" ;;
    *)
        echo "quartz-sonic install: no published package for architecture '$arch' yet (amd64 only)" >&2
        exit 1
        ;;
esac

url="https://github.com/$REPO/releases/latest/download/$deb"
tmp="$(mktemp /tmp/quartz-sonic.XXXXXX.deb)"
trap 'rm -f "$tmp"' EXIT INT TERM

echo "quartz-sonic install: fetching $url"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmp"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmp" "$url"
else
    echo "quartz-sonic install: need curl or wget" >&2
    exit 1
fi

dpkg -i "$tmp"

echo
quartz-sonic status || true
echo
echo "quartz-sonic install: done. Not enrolled yet? Generate a token in the"
echo "Quartz Command console and run:  sudo quartz-sonic enroll '<TOKEN>'"
