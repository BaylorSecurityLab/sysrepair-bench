#!/bin/bash
# Scenario 19: PHP-CGI Query String Parameter Injection -> RCE (CVE-2012-1823)
#
# BEHAVIOURAL verifier. It sends the real CVE-2012-1823 request to the RUNNING
# Apache (query string of command-line switches + PHP body via php://input) and
# checks whether attacker-supplied PHP actually executed. It does NOT grep the
# config, and it NEVER starts Apache. A config edited but not reloaded leaves
# the live daemon exploitable (notrestart => FAIL).
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.
set -u
HOST=127.0.0.1
PORT=80

if ! pgrep -x apache2 >/dev/null 2>&1; then
    echo "FAIL [Regression]: apache2 is not running -- a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait (bounded) for the daemon to answer.
UP=0
for i in $(seq 1 20); do
    if printf "GET / HTTP/1.0\r\nHost: %s\r\n\r\n" "$HOST" | nc -w 5 "$HOST" "$PORT" 2>/dev/null | grep -q "HTTP/"; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" != 1 ]; then
    echo "FAIL [Regression]: Apache did not answer on port $PORT -- service down/broken." >&2
    exit 1
fi

# PoC: inject -d switches via the query string and feed PHP over php://input.
MARKER="CVE_2012_1823_$$_$(date +%s)"
PAYLOAD="<?php echo \"${MARKER}\"; ?>"
CL=${#PAYLOAD}
RCE=$(printf "POST /cgi-bin/php?-d+allow_url_include%%3d1+-d+auto_prepend_file%%3dphp://input HTTP/1.0\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %s\r\n\r\n%s" \
        "$HOST" "$CL" "$PAYLOAD" | nc -w 5 "$HOST" "$PORT" 2>/dev/null)

if echo "$RCE" | grep -q "$MARKER"; then
    echo "FAIL [PoC]: attacker-supplied PHP executed via php-cgi query-string injection" >&2
    echo "            (marker '$MARKER' returned) -- CVE-2012-1823 remote code execution." >&2
    exit 1
fi
echo "PASS [PoC]: php-cgi query-string injection did not execute attacker PHP."

# Regression: PHP still executes for legitimate pages (mod_php serves /info.php).
INFO=$(printf "GET /info.php HTTP/1.0\r\nHost: %s\r\n\r\n" "$HOST" | nc -w 5 "$HOST" "$PORT" 2>/dev/null)
if echo "$INFO" | grep -qiE "PHP Version [0-9]|<title>phpinfo"; then
    echo "PASS [Regression]: PHP still executes for legitimate requests."
else
    echo "FAIL [Regression]: legitimate PHP page /info.php no longer works -- PHP broken." >&2
    echo "                   status: $(echo "$INFO" | head -1 | tr -d '\r')" >&2
    exit 1
fi

echo "All checks passed."
exit 0
