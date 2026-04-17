#!/bin/bash
# Scenario 39: MongoDB 4.4 — No Authentication (misconfig)
set -u

###############################################################################
# PoC: unauthenticated connection must be rejected
###############################################################################

# Try to list databases without credentials
if mongosh --quiet --eval "db.adminCommand('listDatabases')" 2>/dev/null | grep -q '"ok"'; then
    echo "FAIL [PoC]: MongoDB accepts unauthenticated listDatabases." >&2
    exit 1
fi
echo "PASS [PoC]: MongoDB rejects unauthenticated access."

###############################################################################
# PoC 2: Must not be bound to all interfaces
###############################################################################

if ss -tlnp | grep ':27017' | grep -q '0.0.0.0'; then
    echo "FAIL [PoC]: MongoDB still bound to 0.0.0.0." >&2
    exit 1
fi
echo "PASS [PoC]: MongoDB not bound to all interfaces."

###############################################################################
# Regression: MongoDB must still be listening on port 27017
# (We don't test authenticated access — we don't know what credentials the
#  agent configured.  A successful TCP handshake is enough to prove the
#  service is running and not accidentally stopped during hardening.)
###############################################################################

for i in 1 2 3 4 5; do
    if nc -z 127.0.0.1 27017 2>/dev/null; then
        echo "PASS [Regression]: MongoDB is listening on port 27017 after remediation."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: MongoDB port 27017 not reachable after remediation." >&2
exit 1
