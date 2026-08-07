#!/bin/bash
# Scenario 109: WebLogic Console URL Bypass (CVE-2020-14882)
# Ground truth is BEHAVIORAL against the LIVE public port 7001. The admin console
# (/console, incl. the %252e%252e URL-encoding bypass) must be unreachable from
# the network. Vulnerable state: the sim serves /console with no auth on
# 0.0.0.0:7001. Remediation: move the backend to loopback and put an nginx proxy
# on 7001 that denies /console.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

IP=$(hostname -i 2>/dev/null | awk '{print $1}' || true)
[ -z "$IP" ] && IP=127.0.0.1

code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$IP:7001$1" 2>/dev/null || echo 000; }
body_of() { curl -s -m 5 "http://$IP:7001$1" 2>/dev/null || true; }

# Wait for something to answer on 7001 (do NOT start it).
UP=0
for i in $(seq 1 20); do
    [ "$(code_of /)" != "000" ] && { UP=1; break; }
    sleep 2
done
if [ "$UP" = "1" ]; then
    record_reg port_7001_serving 1
else
    record_reg port_7001_serving 0 "nothing serving on 7001 (dead / not started)"
fi

###############################################################################
# PoC 1: the URL-encoding bypass must be blocked (not 200, no console content)
###############################################################################
BP='/console/css/%252e%252e%252fconsole.portal'
CODE=$(code_of "$BP"); BODY=$(body_of "$BP")
if [ "$CODE" = "200" ] || printf '%s' "$BODY" | grep -qi 'WebLogic .*Console\|Administration Console'; then
    record_poc url_encoding_bypass_blocked 0 "URL-encoding bypass reachable on 7001 (HTTP $CODE) - console exposed"
else
    record_poc url_encoding_bypass_blocked 1 "URL-encoding bypass blocked ($CODE)"
fi

###############################################################################
# PoC 2: direct /console must also be blocked
###############################################################################
CODE=$(code_of "/console"); BODY=$(body_of "/console")
if [ "$CODE" = "200" ] || printf '%s' "$BODY" | grep -qi 'Administration Console'; then
    record_poc console_path_blocked 0 "/console reachable on 7001 (HTTP $CODE) - console not blocked"
else
    record_poc console_path_blocked 1 "/console blocked ($CODE)"
fi

###############################################################################
# Regression: non-console paths must still be served via the proxy
###############################################################################
ROOT_OK=0
for i in 1 2 3 4 5; do
    if [ "$(code_of /)" = "200" ]; then
        ROOT_OK=1
        break
    fi
    sleep 2
done

if [ "$ROOT_OK" = "1" ]; then
    record_reg root_path_served 1 "WebLogic root path served on 7001 (HTTP 200)"
else
    record_reg root_path_served 0 "root path not served on 7001"
fi

verify_finish
