#!/bin/bash
# Scenario 114: Cacti Command Injection + nginx WAF (CVE-2022-46169)
# Ground truth is BEHAVIORAL. remote_agent.php is an unauthenticated
# command-injection endpoint. The vulnerable state serves it on 0.0.0.0:8080 —
# an attacker reaching the container's network address hits it directly.
# Remediation: rebind Apache to loopback and front it with an nginx proxy that
# denies remote_agent.php.
set -u
IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1

body_of() { curl -s -m 5 "http://$1/remote_agent.php" 2>/dev/null || true; }
code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$1/remote_agent.php" 2>/dev/null || echo 000; }

###############################################################################
# PoC 1: remote_agent.php must NOT be reachable on the container's public address
###############################################################################
OUT=$(body_of "$IP:8080")
if printf '%s' "$OUT" | grep -qiE 'REMOTE_AGENT_RESPONSE|polled_host'; then
    echo "FAIL [PoC]: remote_agent.php reachable on public interface $IP:8080 — command-injection endpoint exposed." >&2
    exit 1
fi
echo "PASS [PoC]: remote_agent.php not reachable on public $IP:8080."

###############################################################################
# PoC 2: nginx on :80 must deny remote_agent.php (403) and never proxy it
###############################################################################
CODE=$(code_of "127.0.0.1:80")
if [ "$CODE" = "000" ]; then
    echo "FAIL [PoC]: nginx not responding on :80 (proxy not deployed/started)." >&2
    exit 1
fi
BODY=$(body_of "127.0.0.1:80")
if printf '%s' "$BODY" | grep -qiE 'REMOTE_AGENT_RESPONSE|polled_host'; then
    echo "FAIL [PoC]: remote_agent.php served through nginx (HTTP $CODE) — proxy not blocking." >&2
    exit 1
fi
if [ "$CODE" != "403" ]; then
    echo "FAIL [PoC]: remote_agent.php via nginx returned $CODE, expected 403 (deny)." >&2
    exit 1
fi
echo "PASS [PoC]: remote_agent.php denied by nginx (403)."

###############################################################################
# Regression: nginx must still serve the Cacti login page
###############################################################################
for i in 1 2 3 4 5; do
    H=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:80/" 2>/dev/null || echo 000)
    if [ "$H" = "200" ]; then
        BODY=$(curl -s -m 5 "http://127.0.0.1:80/" 2>/dev/null || true)
        if printf '%s' "$BODY" | grep -qiE 'cacti|login|network'; then
            echo "PASS [Regression]: nginx serves the Cacti login page (HTTP 200)."
            exit 0
        fi
        echo "PASS [Regression]: nginx serves / (HTTP 200)."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: nginx did not serve / from the backend." >&2
exit 1
