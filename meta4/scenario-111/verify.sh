#!/bin/bash
# Scenario 111: Memcached 1.6 — UDP Amplification (CVE-2018-1000115)
# Ground truth is BEHAVIORAL against the LIVE daemon: we fire a real memcached
# UDP `stats` datagram at 11211. If the daemon answers over UDP, the reflection/
# amplification vector is live -> FAIL. The daemon boots already-running
# (.preserve-cmd), so disabling UDP in intent but not restarting still leaves the
# UDP socket bound and FAILs here.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

###############################################################################
# PoC: real UDP amplification probe. memcached UDP frame = 8-byte header
# (req-id, seq=0, n-datagrams=1, reserved) followed by the ascii command.
###############################################################################
udp_stats() {
    timeout 3 bash -c '
        exec 3<>/dev/udp/127.0.0.1/11211 || exit 1
        printf "\x13\x37\x00\x00\x00\x01\x00\x00stats\r\n" >&3
        cat <&3
    ' 2>/dev/null
}

RESP=$(udp_stats || true)
if printf '%s' "$RESP" | grep -q "STAT "; then
    record_poc udp_stats_unanswered 0 "memcached answered a UDP stats query - amplification vector is live"
else
    record_poc udp_stats_unanswered 1
fi

# Corroborate with the socket table (ss is present via iproute2).
if ss -uln 2>/dev/null | grep -qE '(:|\.)11211\b'; then
    record_poc udp_11211_unbound 0 "UDP port 11211 is still bound - amplification attack possible"
else
    record_poc udp_11211_unbound 1
fi

###############################################################################
# Regression: TCP service on 11211 must still respond with STAT lines.
# (netcat-openbsd here has no -q, so speak the protocol over /dev/tcp.)
###############################################################################
tcp_stats() {
    timeout 4 bash -c '
        exec 3<>/dev/tcp/127.0.0.1/11211 || exit 1
        printf "stats\r\n" >&3
        # read until we see END or the socket closes
        while IFS= read -r line <&3; do
            printf "%s\n" "$line"
            case "$line" in *END*) break;; esac
        done
    ' 2>/dev/null
}

TCP_OK=0
for i in 1 2 3 4 5; do
    STATS=$(tcp_stats || true)
    if printf '%s' "$STATS" | grep -q "^STAT "; then
        TCP_OK=1
        break
    fi
    sleep 2
done

if [ "$TCP_OK" = "1" ]; then
    record_reg memcached_tcp_serves 1 "memcached TCP responds with STAT lines on port 11211"
else
    record_reg memcached_tcp_serves 0 "memcached TCP does not return STAT lines on port 11211"
fi

verify_finish
