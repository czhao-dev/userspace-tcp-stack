#!/usr/bin/env bash
# Removes the tun0 device created by setup_tun.sh. Safe to run even
# if the interface was never created (e.g. a fresh container).
set -euo pipefail

IFACE="${1:-tun0}"

if ip link show "$IFACE" >/dev/null 2>&1; then
    ip link set "$IFACE" down 2>/dev/null || true
    ip tuntap del dev "$IFACE" mode tun
    echo "Removed $IFACE"
else
    echo "$IFACE does not exist, nothing to do"
fi
