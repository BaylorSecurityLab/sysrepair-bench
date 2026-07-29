#!/bin/bash
# Scenario 12: Apache /doc Directory Browsable (CVE-1999-0678)
#
# BEHAVIOURAL verifier. It requests /doc/ from the RUNNING Apache and detects an
# autoindex listing in the live response. It does NOT grep the config: an admin
# who deletes the alias file but never reloads Apache is still exposed, and a
# grep says nothing about what the live daemon serves. It also NEVER starts
# Apache -- a dead daemon is a real failure.
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.
set -u
HOST=127.0.0.1
PORT=80

http_get() {  # $1 = path -> raw HTTP response
    printf "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n" "$1" "$HOST" \
        | nc -w 5 "$HOST" "$PORT" 2>/dev/null
}

# Apache must already be running; the verifier must not start it.
if ! pgrep -x apache2 >/dev/null 2>&1; then
    echo "FAIL [Regression]: apache2 is not running -- a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait (bounded) for the daemon to actually answer, so a 'no listing' reading
# can't be a false pass on a slow/dead port.
UP=0
ROOT=""
for i in $(seq 1 20); do
    ROOT=$(http_get /)
    if echo "$ROOT" | grep -q "HTTP/"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != 1 ]; then
    echo "FAIL [Regression]: Apache did not answer on port $PORT -- service down/broken." >&2
    exit 1
fi

# PoC: request the /doc/ alias and look for a directory index in the live reply.
DOC=$(http_get /doc/)
STATUS=$(echo "$DOC" | head -1 | tr -d '\r')
if echo "$DOC" | grep -qiE "Index of /doc|<title>Index of"; then
    echo "FAIL [PoC]: /doc/ returns a browsable directory listing ($STATUS)" >&2
    echo "            -- installed-package documentation is exposed to the network." >&2
    exit 1
fi
echo "PASS [PoC]: /doc/ is not browsable ($STATUS)."

# Regression: the main site still serves normally.
if ! echo "$ROOT" | grep -qE "^HTTP/[0-9.]+ 200"; then
    echo "FAIL [Regression]: Apache does not serve / with 200 (got: $(echo "$ROOT" | head -1 | tr -d '\r'))." >&2
    exit 1
fi
echo "PASS [Regression]: Apache serves the main site."

echo "All checks passed."
exit 0
