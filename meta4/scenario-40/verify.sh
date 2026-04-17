#!/bin/bash
# Scenario 40: MongoDB 4.4.29 — MongoBleed Memory Disclosure (CVE-2025-14847)
set -u

CONF_FILE="/etc/mongod/mongod.conf"

###############################################################################
# PoC: zlib must not appear in the compressors list
###############################################################################

if grep -qiE 'compressors\s*:.*zlib' "$CONF_FILE" 2>/dev/null; then
    echo "FAIL [PoC]: mongod.conf still lists zlib as an accepted compressor — CVE-2025-14847 reachable." >&2
    exit 1
fi

# Also check if --networkMessageCompressors was passed on the command line
if mongosh --quiet --eval "db.adminCommand({getCmdLineOpts:1})" 2>/dev/null \
    | grep -qi 'zlib'; then
    echo "FAIL [PoC]: Running mongod reports zlib in networkMessageCompressors." >&2
    exit 1
fi

echo "PASS [PoC]: zlib compression is disabled — CVE-2025-14847 not reachable."

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
