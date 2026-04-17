#!/bin/bash
# Scenario 40: MongoDB 4.4 — Zlib Compression Amplification Risk (misconfiguration)
set -u

CONF_FILE="/etc/mongod/mongod.conf"

###############################################################################
# PoC: zlib must not appear in the compressors list
###############################################################################

if grep -qiE 'compressors\s*:.*zlib' "$CONF_FILE" 2>/dev/null; then
    echo "FAIL [PoC]: mongod.conf still lists zlib as an accepted compressor — compression amplification risk present." >&2
    exit 1
fi

# Also check if --networkMessageCompressors was passed on the command line
if mongosh --quiet --eval "db.adminCommand({getCmdLineOpts:1})" 2>/dev/null \
    | grep -qi 'zlib'; then
    echo "FAIL [PoC]: Running mongod reports zlib in networkMessageCompressors." >&2
    exit 1
fi

echo "PASS [PoC]: zlib compression is disabled — compression amplification risk mitigated."

###############################################################################
# Regression: MongoDB must still respond to a ping
###############################################################################

for i in 1 2 3 4 5; do
    if mongosh --quiet --eval "db.runCommand({ping:1})" 2>/dev/null | grep -q '"ok"'; then
        echo "PASS [Regression]: MongoDB responds to ping after disabling zlib."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: MongoDB not reachable after remediation." >&2
exit 1
