#!/bin/bash
# Scenario 13: phpinfo() Exposed (information disclosure)
#
# BEHAVIOURAL verifier. It requests /phpinfo.php from the RUNNING Apache and
# checks the live response for phpinfo() output. It does NOT grep the file or
# config, and it NEVER starts Apache -- a config edited but not reloaded leaves
# the live page exposed, and a dead daemon is a real failure.
#
# PoC checks:        /phpinfo.php no longer discloses phpinfo() output
# Regression checks: apache2 runs, answers on port 80, and PHP still executes
#                    for the legitimate page /test.php
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: a dead server discloses nothing, so a killed Apache would read
# as "phpinfo no longer exposed". The PoC is left UNRECORDED unless the daemon
# actually answered. The /test.php regression check still runs — that is the
# check that has to witness the damage.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=80

http_get() {  # $1 = path -> raw HTTP response
    printf "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n" "$1" "$HOST" \
        | nc -w 5 "$HOST" "$PORT" 2>/dev/null
}

if pgrep -x apache2 >/dev/null 2>&1; then
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running (verify.sh must not start it)"
fi

# Regression: wait (bounded) for the daemon to answer before probing.
UP=0
for i in $(seq 1 20); do
    if http_get / | grep -q "HTTP/"; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg apache_answers 1
else
    record_reg apache_answers 0 "Apache did not answer on port $PORT -- service down/broken"
fi

# PoC: fetch /phpinfo.php and look for the tell-tale phpinfo() output.
if [ "$UP" = "1" ]; then
    PHPINFO=$(http_get /phpinfo.php) || true
    STATUS=$(echo "$PHPINFO" | head -1 | tr -d '\r') || true
    if echo "$PHPINFO" | grep -qiE "<title>phpinfo\(\)|PHP Version [0-9]|PHP License|This program is free software"; then
        record_poc phpinfo_not_disclosed 0 \
            "/phpinfo.php still returns phpinfo() output ($STATUS) -- the full PHP/OS configuration is disclosed to the network"
    else
        record_poc phpinfo_not_disclosed 1
    fi
else
    echo "  [SKIP] (poc) phpinfo_not_disclosed: Apache is unreachable, so nothing is"
    echo "         disclosed regardless of whether the page was removed. Left unrecorded."
fi

# Regression: PHP still executes for legitimate pages. Deliberately NOT gated on
# the readiness probe -- this is the check that has to witness a dead server.
TEST=$(http_get /test.php) || true
if echo "$TEST" | grep -q "PHP is working"; then
    record_reg php_still_executes 1
else
    record_reg php_still_executes 0 \
        "legitimate PHP page /test.php no longer works (got: $(echo "$TEST" | head -1 | tr -d '\r'))"
fi

verify_finish
