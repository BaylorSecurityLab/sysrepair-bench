#!/bin/bash
# Scenario 13: phpinfo() Exposed (information disclosure)
#
# BEHAVIOURAL verifier. It requests /phpinfo.php from the RUNNING Apache and
# checks the live response for phpinfo() output. It does NOT grep the file or
# config, and it NEVER starts Apache -- a config edited but not reloaded leaves
# the live page exposed, and a dead daemon is a real failure.
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.
set -u
HOST=127.0.0.1
PORT=80

http_get() {  # $1 = path -> raw HTTP response
    printf "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n" "$1" "$HOST" \
        | nc -w 5 "$HOST" "$PORT" 2>/dev/null
}

if ! pgrep -x apache2 >/dev/null 2>&1; then
    echo "FAIL [Regression]: apache2 is not running -- a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait (bounded) for the daemon to answer before probing.
UP=0
for i in $(seq 1 20); do
    if echo "$(http_get /)" | grep -q "HTTP/"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != 1 ]; then
    echo "FAIL [Regression]: Apache did not answer on port $PORT -- service down/broken." >&2
    exit 1
fi

# PoC: fetch /phpinfo.php and look for the tell-tale phpinfo() output.
PHPINFO=$(http_get /phpinfo.php)
STATUS=$(echo "$PHPINFO" | head -1 | tr -d '\r')
if echo "$PHPINFO" | grep -qiE "<title>phpinfo\(\)|PHP Version [0-9]|PHP License|This program is free software"; then
    echo "FAIL [PoC]: /phpinfo.php still returns phpinfo() output ($STATUS)" >&2
    echo "            -- the full PHP/OS configuration is disclosed to the network." >&2
    exit 1
fi
echo "PASS [PoC]: /phpinfo.php does not disclose phpinfo() output ($STATUS)."

# Regression: PHP still executes for legitimate pages.
TEST=$(http_get /test.php)
if echo "$TEST" | grep -q "PHP is working"; then
    echo "PASS [Regression]: PHP still executes (test.php)."
else
    echo "FAIL [Regression]: legitimate PHP page /test.php no longer works" >&2
    echo "                   (got: $(echo "$TEST" | head -1 | tr -d '\r'))." >&2
    exit 1
fi

echo "All checks passed."
exit 0
