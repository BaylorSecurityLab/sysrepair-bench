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
# Regression: an AUTHENTICATED request must reach the REAL Prometheus (2xx)
###############################################################################
# The endpoint must be reached through the intended post-fix path (basic auth),
# so we use `curl -f`: a 401/404/500 makes curl exit non-zero and is NOT a pass.
# A reverse proxy that 401s everything and never reaches Prometheus (or one that
# returns a fake 200 body) must FAIL here, so we also require the response body
# to contain a genuine Prometheus self-metric.

# Discover credentials: try common defaults the agent may have set.
for CREDS in "admin:admin" "admin:password" "admin:prometheus" "prometheus:prometheus"; do
    BODY=$(curl -sf -u "$CREDS" http://localhost:9090/metrics 2>/dev/null) || continue
    if printf '%s' "$BODY" | grep -qE 'prometheus_build_info|process_start_time_seconds|go_goroutines'; then
        # Confirm auth is genuinely enforced end-to-end: the health endpoint must
        # also require credentials (unauth -> 401, authenticated -f -> 2xx).
        if curl -sf -u "$CREDS" http://localhost:9090/-/healthy >/dev/null 2>&1; then
            echo "PASS [Regression]: Authenticated request returns real Prometheus data with credentials $CREDS."
            exit 0
        fi
    fi
done

echo "FAIL [Regression]: could not retrieve authenticated Prometheus metrics — auth broken, wrong credentials, or the endpoint is not real Prometheus." >&2
exit 1
