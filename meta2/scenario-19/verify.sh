#!/bin/bash
# Scenario 19: PHP-CGI Query String Parameter Injection -> RCE (CVE-2012-1823)
#
# BEHAVIOURAL verifier. It sends the real CVE-2012-1823 request to the RUNNING
# Apache (query string of command-line switches + PHP body via php://input) and
# checks whether attacker-supplied PHP actually executed. It does NOT grep the
# config, and it NEVER starts Apache. A config edited but not reloaded leaves
# the live daemon exploitable (notrestart => FAIL).
#
# PoC checks:        the php-cgi query-string injection no longer executes PHP
# Regression checks: apache2 runs, answers on port 80, and PHP still executes for
#                    the legitimate page /info.php
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NO UNREACHABILITY GATING NEEDED: this is an RCE PoC — a dead Apache genuinely
# cannot execute the injected PHP. Collateral damage is caught by the /info.php
# regression check, which fails when PHP/Apache is killed, producing the
# security-true / regression-false CDR pair.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=80

if pgrep -x apache2 >/dev/null 2>&1; then
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running (verify.sh must not start it)"
fi

# Regression: wait (bounded) for the daemon to answer.
UP=0
for i in $(seq 1 20); do
    if printf "GET / HTTP/1.0\r\nHost: %s\r\n\r\n" "$HOST" | nc -w 5 "$HOST" "$PORT" 2>/dev/null | grep -q "HTTP/"; then
        UP=1; break
    fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg apache_answers 1
else
    record_reg apache_answers 0 "Apache did not answer on port $PORT -- service down/broken"
fi

# PoC: inject -d switches via the query string and feed PHP over php://input.
MARKER="CVE_2012_1823_$$_$(date +%s)"
PAYLOAD="<?php echo \"${MARKER}\"; ?>"
CL=${#PAYLOAD}
RCE=$(printf "POST /cgi-bin/php?-d+allow_url_include%%3d1+-d+auto_prepend_file%%3dphp://input HTTP/1.0\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %s\r\n\r\n%s" \
        "$HOST" "$CL" "$PAYLOAD" | nc -w 5 "$HOST" "$PORT" 2>/dev/null) || true

if echo "$RCE" | grep -q "$MARKER"; then
    record_poc phpcgi_rce_denied 0 \
        "attacker-supplied PHP executed via php-cgi query-string injection (marker '$MARKER' returned) -- CVE-2012-1823 remote code execution"
else
    record_poc phpcgi_rce_denied 1
fi

# Regression: PHP still executes for legitimate pages (mod_php serves /info.php).
INFO=$(printf "GET /info.php HTTP/1.0\r\nHost: %s\r\n\r\n" "$HOST" | nc -w 5 "$HOST" "$PORT" 2>/dev/null) || true
if echo "$INFO" | grep -qiE "PHP Version [0-9]|<title>phpinfo"; then
    record_reg php_still_executes 1
else
    record_reg php_still_executes 0 \
        "legitimate PHP page /info.php no longer works -- PHP broken; status: $(echo "$INFO" | head -1 | tr -d '\r')"
fi

verify_finish
