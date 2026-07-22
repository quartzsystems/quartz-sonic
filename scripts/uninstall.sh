#!/bin/sh
# quartz-sonic uninstaller for SONiC switches.
#
#   curl -fsSL https://raw.githubusercontent.com/quartzsystems/quartz-sonic/main/scripts/uninstall.sh | sudo sh
#
# Stops and removes the service, purges the package, and deletes all local
# state (identity, certificates, enrollment) under /var/lib/quartz-sonic.
# Pass --keep-state to preserve the identity and enrollment so a later
# reinstall reconnects as the same switch:
#
#   curl -fsSL .../uninstall.sh | sudo sh -s -- --keep-state
#
# Uninstalling does NOT notify the controller. Unless the switch was
# unenrolled first (sudo quartz-sonic unenroll), also revoke/remove the
# device in the Quartz Command console.
set -eu

KEEP_STATE=0
for arg in "$@"; do
    case "$arg" in
        --keep-state) KEEP_STATE=1 ;;
        *)
            echo "quartz-sonic uninstall: unknown option '$arg' (only --keep-state)" >&2
            exit 2
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "quartz-sonic uninstall: must run as root — pipe to 'sudo sh'" >&2
    exit 1
fi

# Stop the daemon before dpkg touches anything so the control channel closes
# cleanly instead of racing the file removal.
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop quartz-sonic.service 2>/dev/null || true
    systemctl disable quartz-sonic.service 2>/dev/null || true
fi

if dpkg -s quartz-sonic >/dev/null 2>&1; then
    echo "quartz-sonic uninstall: purging package"
    dpkg --purge quartz-sonic
else
    # Not registered with dpkg (e.g. a hand-copied binary) — remove the same
    # files the package would own.
    echo "quartz-sonic uninstall: package not installed per dpkg; removing files directly"
    rm -f /usr/bin/quartz-sonic \
        /usr/lib/systemd/system/quartz-sonic.service \
        /lib/systemd/system/quartz-sonic.service
    rm -rf /usr/share/doc/quartz-sonic
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || true
    fi
fi

# Live status dir (tmpfs, but clear it now rather than at next reboot).
rm -rf /run/quartz-sonic

if [ "$KEEP_STATE" -eq 1 ]; then
    echo "quartz-sonic uninstall: kept /var/lib/quartz-sonic — reinstalling later"
    echo "reconnects this switch under the same device ID."
else
    rm -rf /var/lib/quartz-sonic /etc/quartz-sonic
    echo "quartz-sonic uninstall: all local state removed."
    echo "If this switch was enrolled, also revoke/remove the device in the"
    echo "Quartz Command console — uninstalling does not notify the controller."
fi

echo "quartz-sonic uninstall: done"
