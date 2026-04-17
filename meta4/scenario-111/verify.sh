#!/bin/bash
# Scenario 111: Memcached 1.6 — UDP Amplification (CVE-2018-1000115)
set -u

###############################################################################
# PoC: UDP port 11211 must NOT be open
###############################################################################

if ss -ulnp | grep -q ':11211'; then
    echo "FAIL [PoC]: UDP port 11211 is still open — amplification attack possible." >&2
    exit 1
fi
echo "PASS [PoC]: UDP port 11211 is not listening."

###############################################################################
# Regression: TCP service on 11211 must still respond with STAT lines
###############################################################################

for i in 1 2 3 4 5; do
    STATS=$(echo "stats" | nc -q1 127.0.0.1 11211 2>/dev/null || true)
    if echo "$STATS" | grep -q "^STAT "; then
        echo "PASS [Regression]: Memcached TCP responds with STAT lines."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: Memcached TCP does not return STAT lines on port 11211." >&2
exit 1
