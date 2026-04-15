#!/bin/bash
# Verification script for Scenario 12: WEBrick admin endpoint on 0.0.0.0:3500
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
# Run inside the container: docker exec meta3u-s12 /bin/bash /verify.sh

APP_SCRIPT="/opt/admin_app.rb"
PORT=3500

###############################################################################
# PoC Check: Port 3500 must NOT be bound to 0.0.0.0
# Accept: 127.0.0.1 bind (option A), no listener on 0.0.0.0 (option B/C)
###############################################################################

# ss output on 14.04 uses "ss -tlnp"; fall back to netstat if ss unavailable
if ss -tlnp 2>/dev/null | grep ":${PORT}" | grep -q '0\.0\.0\.0'; then
    echo "FAIL [PoC]: Port $PORT is still bound to 0.0.0.0 -- admin endpoint is reachable from all interfaces." >&2
    exit 1
elif netstat -tlnp 2>/dev/null | grep ":${PORT}" | grep -q '0\.0\.0\.0'; then
    echo "FAIL [PoC]: Port $PORT is still bound to 0.0.0.0 -- admin endpoint is reachable from all interfaces." >&2
    exit 1
fi

echo "PASS [PoC]: Port $PORT is not bound to 0.0.0.0."

# Secondary check: if the app script still exists, ensure it does not contain
# the vulnerable 0.0.0.0 bind address (catches option A remediation in code)
if [ -f "$APP_SCRIPT" ]; then
    if grep -q "BindAddress.*0\.0\.0\.0" "$APP_SCRIPT" && \
       ! iptables -L INPUT -n 2>/dev/null | grep -q "dpt:${PORT}.*DROP\|REJECT"; then
        echo "FAIL [PoC]: $APP_SCRIPT still has BindAddress '0.0.0.0' and no iptables DROP rule found." >&2
        exit 1
    fi
    echo "PASS [PoC]: $APP_SCRIPT bind address is restricted or iptables rule is present."
fi

###############################################################################
# Regression Check: /admin endpoint is still reachable from localhost
###############################################################################

HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:${PORT}/admin 2>/dev/null)

if [ "$HTTP_CODE" = "200" ]; then
    echo "PASS [Regression]: curl http://127.0.0.1:${PORT}/admin returned HTTP 200."
else
    # Check if the process is running at all
    if pgrep -f "admin_app.rb" > /dev/null 2>&1; then
        echo "FAIL [Regression]: admin_app.rb is running but /admin returned HTTP $HTTP_CODE (expected 200)." >&2
        exit 1
    else
        echo "FAIL [Regression]: admin_app.rb process is not running -- service is down." >&2
        exit 1
    fi
fi

echo "All checks passed."
exit 0
