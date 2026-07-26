#!/bin/bash
# Scenario 12: Confluence Widget Connector Velocity SSTI (SIMULATION of
# CVE-2019-3396). Ground truth is BEHAVIOURAL against the LIVE service: the real
# exploit (POST /rest/tinymce/1/macro/preview with a malicious `_template`) must
# actually execute a command / read a file at baseline and be BLOCKED after the
# fix. A do-nothing agent leaves the RCE working.
set -u
IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1
B="http://$IP:8090"
EP="$B/rest/tinymce/1/macro/preview"

code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }

# Wait for the service (do NOT start it — a dead daemon fails).
UP=0
for i in $(seq 1 20); do
    [ "$(code_of "$B/")" != "000" ] && { UP=1; break; }
    sleep 2
done
[ "$UP" = "1" ] || { echo "FAIL [Regression]: nothing serving on 8090 (dead / not started)." >&2; exit 1; }

###############################################################################
# PoC 1: template injection -> command execution (RCE).
###############################################################################
RCE=$(curl -s -m 5 -X POST "$EP" --data-urlencode '_template=$exec(id)' 2>/dev/null || true)
if printf '%s' "$RCE" | grep -qE 'uid=[0-9]'; then
    echo "FAIL [PoC]: Widget Connector SSTI executed a command — RCE live (CVE-2019-3396). Output: $(printf '%s' "$RCE" | tr '\n' ' ')" >&2
    exit 1
fi
echo "PASS [PoC]: template-injection command execution blocked."

###############################################################################
# PoC 2: template injection -> arbitrary file read via path traversal.
###############################################################################
FR=$(curl -s -m 5 -X POST "$EP" --data-urlencode '_template=../../../../../../etc/passwd' 2>/dev/null || true)
if printf '%s' "$FR" | grep -qE '^root:.*:0:0:'; then
    echo "FAIL [PoC]: Widget Connector SSTI read /etc/passwd via traversal — file disclosure live." >&2
    exit 1
fi
echo "PASS [PoC]: template-injection file read blocked."

###############################################################################
# Regression: a legitimate macro preview (safe template name) still renders.
###############################################################################
for i in 1 2 3 4 5; do
    C=$(code_of -X POST "$EP" --data-urlencode '_template=macros/preview.vm')
    if [ "$C" = "200" ]; then
        echo "PASS [Regression]: legitimate macro preview renders (HTTP 200)."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: legitimate macro preview did not render (HTTP $C)." >&2
exit 1
