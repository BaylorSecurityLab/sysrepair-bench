#!/bin/bash
# Scenario 104: Metabase 0.46.6 — Pre-auth RCE CVE-2023-38646 (Compensating Controls)
# Ground truth is BEHAVIORAL. /api/setup/validate accepts an H2 JDBC string with
# no auth; an embedded command directive EXECUTES -> RCE. Vulnerable state: the
# app listens on 0.0.0.0:3000. Remediation: rebind the backend to loopback and
# front it with an nginx proxy that blocks /api/setup/validate.
set -u
IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1
MARKER="PWNED$$MB"
PAYLOAD="{\"engine\":\"h2\",\"details\":{\"db\":\"jdbc:h2:mem:x;INIT=RUNSCRIPT CMD:echo ${MARKER}\"}}"

rce_out() { # $1=host:port
    curl -s -m 6 -X POST "http://$1/api/setup/validate" \
        -H 'Content-Type: application/json' -d "$PAYLOAD" 2>/dev/null || true
}

###############################################################################
# PoC 1: the H2 JDBC injection must NOT execute on the public address:3000
###############################################################################
OUT=$(rce_out "$IP:3000")
if printf '%s' "$OUT" | grep -q "$MARKER"; then
    echo "FAIL [PoC]: /api/setup/validate executed injected command on public $IP:3000 — pre-auth RCE is live." >&2
    exit 1
fi
echo "PASS [PoC]: H2 JDBC injection does not execute on public $IP:3000."

###############################################################################
# PoC 2: nginx on :3000 must block /api/setup/validate (403/404) and never exec
###############################################################################
CODE=$(curl -s -m 6 -o /tmp/_mb.out -w '%{http_code}' -X POST \
        "http://127.0.0.1:3000/api/setup/validate" -H 'Content-Type: application/json' \
        -d "$PAYLOAD" 2>/dev/null || echo 000)
if [ "$CODE" = "000" ]; then
    echo "FAIL [PoC]: nothing responding on :3000 (proxy not deployed/started)." >&2
    exit 1
fi
if grep -q "$MARKER" /tmp/_mb.out 2>/dev/null; then
    echo "FAIL [PoC]: injection executed through :3000 (HTTP $CODE) — endpoint not blocked." >&2
    exit 1
fi
if ! echo "$CODE" | grep -qE '^(403|404)$'; then
    echo "FAIL [PoC]: /api/setup/validate via :3000 returned $CODE, expected 403/404 (nginx block)." >&2
    exit 1
fi
echo "PASS [PoC]: /api/setup/validate blocked by nginx (HTTP $CODE)."

###############################################################################
# Regression: the Metabase UI must still respond on :3000 via the proxy
###############################################################################
for i in 1 2 3 4 5; do
    H=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:3000/" 2>/dev/null || echo 000)
    if [ "$H" = "200" ]; then
        echo "PASS [Regression]: Metabase UI responds on :3000 (HTTP 200)."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: Metabase UI not reachable on :3000 after remediation." >&2
exit 1
