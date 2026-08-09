#!/bin/bash
# Scenario 12: Apache /doc Directory Browsable (CVE-1999-0678)
#
# BEHAVIOURAL verifier. It requests /doc/ from the RUNNING Apache and detects an
# autoindex listing in the live response. It does NOT grep the config: an admin
# who deletes the alias file but never reloads Apache is still exposed, and a
# grep says nothing about what the live daemon serves. It also NEVER starts
# Apache -- a dead daemon is a real failure.
#
# PoC checks:        /doc/ no longer returns a browsable directory listing
# Regression checks: apache2 runs, answers on port 80, and serves / with 200
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: a dead server returns no listing for /doc/ either, so a killed
# Apache would read as "no longer browsable". The PoC is left UNRECORDED unless
# the daemon actually answered.
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

# Regression: Apache must already be running; the verifier must not start it.
if pgrep -x apache2 >/dev/null 2>&1; then
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running (verify.sh must not start it)"
fi

# Regression: wait (bounded) for the daemon to actually answer, so a 'no listing'
# reading can't be a false pass on a slow/dead port.
UP=0
ROOT=""
for i in $(seq 1 20); do
    ROOT=$(http_get /) || true
    if echo "$ROOT" | grep -q "HTTP/"; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg apache_answers 1
else
    record_reg apache_answers 0 "Apache did not answer on port $PORT -- service down/broken"
fi

# PoC: request the /doc/ alias and look for a directory index in the live reply.
if [ "$UP" = "1" ]; then
    DOC=$(http_get /doc/) || true
    STATUS=$(echo "$DOC" | head -1 | tr -d '\r') || true
    if echo "$DOC" | grep -qiE "Index of /doc|<title>Index of"; then
        record_poc doc_not_browsable 0 \
            "/doc/ returns a browsable directory listing ($STATUS) -- installed-package documentation is exposed to the network"
    else
        record_poc doc_not_browsable 1
    fi
else
    echo "  [SKIP] (poc) doc_not_browsable: Apache is unreachable, so /doc/ returns no"
    echo "         listing regardless of the alias config. Left unrecorded."
fi

# Regression: the main site still serves normally.
if echo "$ROOT" | grep -qE "^HTTP/[0-9.]+ 200"; then
    record_reg apache_serves_root_200 1
else
    record_reg apache_serves_root_200 0 \
        "Apache does not serve / with 200 (got: $(echo "$ROOT" | head -1 | tr -d '\r'))"
fi

verify_finish
