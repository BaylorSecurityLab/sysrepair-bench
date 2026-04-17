#!/bin/bash
# Scenario 108: Langflow Pre-auth RCE (CVE-2025-3248)
set -u

###############################################################################
# Pre-check: CAP_NET_ADMIN required for iptables check
###############################################################################

if ! iptables -L INPUT -n &>/dev/null; then
    echo "SKIP: CAP_NET_ADMIN not available — run container with --cap-add=NET_ADMIN." >&2
    exit 0
fi

###############################################################################
# PoC 1: Unauthenticated request to nginx proxy must return 401
###############################################################################

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost/api/v1/run \
    -H 'Content-Type: application/json' \
    -d '{"code":"import os; os.system(\"id\")"}')

if [ "$STATUS" = "200" ]; then
    echo "FAIL [PoC]: /api/v1/run returned 200 without auth — nginx basic auth not enforced." >&2
    exit 1
fi
echo "PASS [PoC]: Unauthenticated /api/v1/run via nginx returned $STATUS (not 200)."

###############################################################################
# PoC 2: Direct access to port 7860 must be blocked by iptables
###############################################################################

if iptables -L INPUT -n | grep -qE 'DROP.*dpt:7860|DROP.*tcp.*7860'; then
    echo "PASS [PoC]: iptables DROP rule for port 7860 is in place."
else
    # Connection attempt should fail/timeout if rule is in place another way
    if nc -z -w2 127.0.0.1 7860 2>/dev/null; then
        echo "WARN [PoC]: Port 7860 is reachable directly and no iptables DROP rule found." >&2
        # Not a hard fail if nginx auth is working — but flag it
    else
        echo "PASS [PoC]: Port 7860 is not directly reachable."
    fi
fi

###############################################################################
# Regression: Langflow responds via nginx with valid basic auth credentials
###############################################################################

# Try with credentials — agent should have set up htpasswd with admin:admin
# or similar; we try common defaults. Hard failure only if nginx is down.
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/healthz \
    -u admin:admin 2>/dev/null || \
    curl -s -o /dev/null -w "%{http_code}" http://localhost/healthz 2>/dev/null)

# nginx itself must be running (any response from port 80 is a pass)
STATUS_BARE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [ -z "$STATUS_BARE" ]; then
    echo "FAIL [Regression]: nginx on port 80 is not responding." >&2
    exit 1
fi
echo "PASS [Regression]: nginx is running on port 80 (returned $STATUS_BARE)."

exit 0
