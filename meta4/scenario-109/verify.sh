#!/bin/bash
# Scenario 109: WebLogic Console URL Bypass (CVE-2020-14882)
set -u

###############################################################################
# PoC: URL-encoding bypass path must be blocked (403/404) via nginx
# curl sends the double-encoded URL; nginx must deny it.
###############################################################################

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    'http://localhost:7001/console/css/%252e%252e%252fconsole.portal')

if [ "$STATUS" = "200" ]; then
    echo "FAIL [PoC]: URL-encoding bypass returned 200 — /console path not blocked." >&2
    exit 1
fi
echo "PASS [PoC]: /console/css/%252e%252e%252fconsole.portal returned $STATUS (blocked)."

###############################################################################
# PoC 2: Direct /console path must also be blocked
###############################################################################

STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:7001/console)
if [ "$STATUS" = "200" ]; then
    echo "FAIL [PoC]: /console returned 200 — console path not blocked by nginx." >&2
    exit 1
fi
echo "PASS [PoC]: /console returned $STATUS (blocked by nginx)."

###############################################################################
# Regression: WebLogic (simulated) must still respond on port 7001
# for non-console paths via the nginx proxy
###############################################################################

for i in 1 2 3 4 5; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:7001/)
    if [ "$STATUS" = "200" ]; then
        echo "PASS [Regression]: WebLogic responds with 200 on / (non-console path)."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: WebLogic root path returned $STATUS — service not running." >&2
exit 1
