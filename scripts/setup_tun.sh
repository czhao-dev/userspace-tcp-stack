#!/usr/bin/env bash
# Creates a persistent tun0 device via `ip tuntap add` (so it exists
# before minitcp runs, matching the README's run order), assigns a
# point-to-point address pair, and brings it up. minitcp's
# tun_alloc() (src/tun.rs) then opens /dev/net/tun and
# ioctl(TUNSETIFF)s onto this existing device by name rather than
# creating a new one.
#
# Point-to-point (LOCAL peer REMOTE) addressing, not a plain subnet,
# is required here: if the kernel treats 10.0.0.1 as a same-subnet
# local address, pings to it are answered directly by the kernel's
# loopback delivery path and never reach the TUN fd at all -- minitcp
# would never see them. With an explicit peer address, traffic to the
# peer (10.0.0.2 -- "minitcp's own" address) is routed out through
# tun0, landing in minitcp's tun_read(), and minitcp's replies (using
# 10.0.0.2 as their source) come back in as locally-deliverable
# packets addressed to LOCAL (10.0.0.1).
IFACE="${1:-tun0}"
LOCAL="${2:-10.0.0.1}"
REMOTE="${3:-10.0.0.2}"

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    ip tuntap add dev "$IFACE" mode tun
fi

ip addr add "$LOCAL" peer "$REMOTE" dev "$IFACE" 2>/dev/null || true
ip link set "$IFACE" up

echo "Configured $IFACE: local=$LOCAL peer(minitcp)=$REMOTE"
echo "Run tools against $REMOTE (e.g. ping $REMOTE) -- not $LOCAL."
ip addr show "$IFACE"
