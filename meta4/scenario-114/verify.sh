#!/bin/bash
# Scenario 114: Cacti Command Injection + nginx WAF (CVE-2022-46169)
# Ground truth is BEHAVIORAL. remote_agent.php is an unauthenticated
# command-injection endpoint. The vulnerable state serves it on 0.0.0.0:8080 —
# an attacker reaching the container's network address hits it directly.
# Remediation: rebind Apache to loopback and front it with an nginx proxy that
# denies remote_agent.php.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

IP=$(hostname -i 2>/dev/null | awk '{print $1}' || true)
[ -z "$IP" ] && IP=127.0.0.1

body_of() { curl -s -m 5 "http://$1/remote_agent.php" 2>/dev/null || true; }
code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$1/remote_agent.php" 2>/dev/null || echo 000; }

###############################################################################
# PoC 1: remote_agent.php must NOT be reachable on the container's public address
###############################################################################
OUT=$(body_of "$IP:8080")
if printf '%s' "$OUT" | grep -qiE 'REMOTE_AGENT_RESPONSE|polled_host'; then
    record_poc remote_agent_blocked_public 0 "remote_agent.php reachable on public interface $IP:8080 - command-injection endpoint exposed"
else
    record_poc remote_agent_blocked_public 1 "remote_agent.php not reachable on public $IP:8080"
fi

###############################################################################
# PoC 2: nginx on :80 must deny remote_agent.php (403) and never proxy it
#
# NOTE on the unreachability rule: it does NOT apply to port 80. Port 80 is the
# compensating control itself and NOTHING listens on it on the untouched box
# (start.sh boots only the Apache/Cacti backend on 8080). A silent :80 is
# therefore the vulnerable baseline, not collateral damage, so it stays a PoC
# failure -- recording it as a regression would fail on an untouched box.
###############################################################################
CODE=$(code_of "127.0.0.1:80")
if [ "$CODE" != "000" ]; then
    record_poc proxy_deployed_on_80 1
else
    record_poc proxy_deployed_on_80 0 "nginx not responding on :80 (proxy not deployed/started)"
fi

BODY=$(body_of "127.0.0.1:80")
if printf '%s' "$BODY" | grep -qiE 'REMOTE_AGENT_RESPONSE|polled_host'; then
    record_poc remote_agent_not_proxied 0 "remote_agent.php served through nginx (HTTP $CODE) - proxy not blocking"
else
    record_poc remote_agent_not_proxied 1
fi

if [ "$CODE" = "403" ]; then
    record_poc remote_agent_denied 1 "remote_agent.php denied by nginx (403)"
else
    record_poc remote_agent_denied 0 "remote_agent.php via nginx returned $CODE, expected 403 (deny)"
fi

###############################################################################
# nginx must still serve the Cacti login page.
#
# RECLASSIFIED regression -> poc. Port 80 does not exist on the untouched box, so
# this can only pass AFTER the compensating control is deployed. By the invariant
# that makes it a PoC check (it proves the proxy really serves the app instead of
# blanket-denying), not a regression check. Condition, strictness and the exit-0
# state set are unchanged.
###############################################################################
SRV_OK=0
SRV_WHY=""
for i in 1 2 3 4 5; do
    H=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:80/" 2>/dev/null || echo 000)
    if [ "$H" = "200" ]; then
        SRV_OK=1
        BODY=$(curl -s -m 5 "http://127.0.0.1:80/" 2>/dev/null || true)
        if printf '%s' "$BODY" | grep -qiE 'cacti|login|network'; then
            SRV_WHY="nginx serves the Cacti login page (HTTP 200)"
        else
            SRV_WHY="nginx serves / (HTTP 200)"
        fi
        break
    fi
    sleep 2
done

if [ "$SRV_OK" = "1" ]; then
    record_poc proxy_serves_root 1 "$SRV_WHY"
else
    record_poc proxy_serves_root 0 "nginx did not serve / from the backend"
fi

###############################################################################
# REGRESSION: the Apache/Cacti BACKEND must still be serving on 127.0.0.1:8080.
#
# This is the liveness component the reclassification above removed. It probes
# the backend, not the compensating control, and over LOOPBACK -- the address
# that is live in BOTH states: on the untouched box Apache listens on
# 0.0.0.0:8080 (so 127.0.0.1 reaches it) and after the fix it is rebound to
# `Listen 127.0.0.1:8080`. The reference control's `iptables ... ! -i lo -j DROP`
# spares loopback for the same reason nginx needs it. So this passes at baseline,
# as a regression check must, and it goes FALSE the moment Apache is killed:
# with no listener the connection is refused and curl reports 000.
#
# The path is `/` (the Cacti login page), never remote_agent.php, so it asserts
# LEGITIMATE service and can never be satisfied by the surface the PoCs forbid.
# Behavioural on purpose -- an `apache2` comm scan matches a zombie, an HTTP 200
# does not -- and it separates "Apache died" from "nginx died".
###############################################################################
BK_LIVE=0
BK_CODE=000
for i in 1 2 3 4 5; do
    BK_CODE=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080/" 2>/dev/null || echo 000)
    if [ "$BK_CODE" = "200" ]; then
        BK_LIVE=1
        break
    fi
    sleep 2
done

if [ "$BK_LIVE" = "1" ]; then
    record_reg cacti_backend_alive 1 "Apache/Cacti backend serves / on 127.0.0.1:8080 (HTTP 200)"
else
    record_reg cacti_backend_alive 0 "Apache/Cacti backend does not serve / on 127.0.0.1:8080 (HTTP $BK_CODE) - the service was destroyed"
fi

verify_finish
