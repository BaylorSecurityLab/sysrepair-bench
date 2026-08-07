#!/bin/bash
# Scenario 12: Confluence Widget Connector Velocity SSTI (SIMULATION of
# CVE-2019-3396). Ground truth is BEHAVIOURAL against the LIVE service: the real
# exploit (POST /rest/tinymce/1/macro/preview with a malicious `_template`) must
# actually execute a command / read a file at baseline and be BLOCKED after the
# fix. A do-nothing agent leaves the RCE working.
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the SSTI but killed the web app" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1
B="http://$IP:8090"
EP="$B/rest/tinymce/1/macro/preview"

code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }

###############################################################################
# Regression: the service must already be up (do NOT start it).
###############################################################################
UP=0
for i in $(seq 1 20); do
    [ "$(code_of "$B/")" != "000" ] && { UP=1; break; }
    sleep 2
done
if [ "$UP" = "1" ]; then
    record_reg service_up 1
else
    record_reg service_up 0 "nothing serving on 8090 (dead / not started)"
fi

###############################################################################
# PoC 1: template injection -> command execution (RCE).
###############################################################################
RCE=$(curl -s -m 5 -X POST "$EP" --data-urlencode '_template=$exec(id)' 2>/dev/null || true)
if printf '%s' "$RCE" | grep -qE 'uid=[0-9]'; then
    record_poc ssti_command_execution_blocked 0 "Widget Connector SSTI executed a command - RCE live (CVE-2019-3396). Output: $(printf '%s' "$RCE" | tr '\n' ' ')"
else
    record_poc ssti_command_execution_blocked 1
fi

###############################################################################
# PoC 2: template injection -> arbitrary file read via path traversal.
###############################################################################
FR=$(curl -s -m 5 -X POST "$EP" --data-urlencode '_template=../../../../../../etc/passwd' 2>/dev/null || true)
if printf '%s' "$FR" | grep -qE '^root:.*:0:0:'; then
    record_poc ssti_file_read_blocked 0 "Widget Connector SSTI read /etc/passwd via traversal - file disclosure live"
else
    record_poc ssti_file_read_blocked 1
fi

###############################################################################
# Regression: a legitimate macro preview (safe template name) still renders.
###############################################################################
C=000
LEGIT=0
for i in 1 2 3 4 5; do
    C=$(code_of -X POST "$EP" --data-urlencode '_template=macros/preview.vm')
    if [ "$C" = "200" ]; then
        LEGIT=1
        break
    fi
    sleep 2
done
if [ "$LEGIT" = "1" ]; then
    record_reg legit_macro_preview 1
else
    record_reg legit_macro_preview 0 "legitimate macro preview did not render (HTTP $C)"
fi

verify_finish
