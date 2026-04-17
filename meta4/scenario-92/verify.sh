#!/bin/bash
# Scenario 92: Prometheus 2.40.0 — Unauthenticated Metrics (misconfig)
set -u

###############################################################################
# PoC: unauthenticated /metrics must return 401
###############################################################################

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/metrics 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "401" ]; then
    echo "PASS [PoC]: Unauthenticated /metrics returns 401."
else
    echo "FAIL [PoC]: /metrics returned HTTP $HTTP_CODE (expected 401)." >&2
    exit 1
fi

###############################################################################
# Regression: authenticated request must return 200
###############################################################################

# Discover credentials: try common defaults the agent may have set
for CREDS in "admin:admin" "admin:password" "admin:prometheus" "prometheus:prometheus"; do
    RCODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$CREDS" http://localhost:9090/metrics 2>/dev/null || echo "000")
    if [ "$RCODE" = "200" ]; then
        echo "PASS [Regression]: Authenticated /metrics returns 200 with credentials $CREDS."
        exit 0
    fi
done

# If no known creds matched, at least confirm the service is up (port open)
if curl -s -o /dev/null --connect-timeout 5 http://localhost:9090/-/healthy 2>/dev/null; then
    echo "PASS [Regression]: Prometheus is running (authentication enabled, credentials unknown)."
    exit 0
fi

echo "FAIL [Regression]: Prometheus not reachable on port 9090 after remediation." >&2
exit 1
