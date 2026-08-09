#!/bin/bash
# CVE-2021-42013 — Apache httpd 2.4.50 double-encoded traversal -> file read/RCE.
# BEHAVIORAL ground truth against the LIVE server on port 80: fire the
# double-encoded `.%%32%65/` traversal at /etc/passwd. 200 + real passwd content
# (root:...:0:0:) => vulnerable. curl/wget/nc are absent, so we use bash
# /dev/tcp. Boots already-running (.preserve-cmd): a config edit without a
# restart still serves the vulnerable config and FAILs here.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "traversal refused because httpd is dead" is reported as regression_pass=false
# rather than collapsing into a bare exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1; PORT=80

http_get() { # $1=path -> raw response
    timeout 6 bash -c '
        exec 3<>/dev/tcp/'"$HOST"'/'"$PORT"' || exit 1
        printf "GET %s HTTP/1.0\r\nHost: x\r\nConnection: close\r\n\r\n" "$1" >&3
        cat <&3
        exec 3<&-
    ' _ "$1" 2>/dev/null || true
}

# Reachability is a REGRESSION check: it is what separates "closed the
# traversal" from "closed it by destroying httpd". It does not abort the run --
# the traversal probe below always fires and reports its own verdict.
UP=0
for i in $(seq 1 30); do
    if http_get "/" | head -1 | grep -q ' 200'; then UP=1; break; fi
    sleep 2
done
if [ "$UP" = "1" ]; then
    record_reg httpd_serving_root 1
else
    record_reg httpd_serving_root 0 "httpd not serving 200 on port 80 (dead/not restarted)"
fi

RESP=$(http_get "/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd")
STATUS=$(printf '%s' "$RESP" | head -1)
if printf '%s' "$STATUS" | grep -q ' 200' && printf '%s' "$RESP" | grep -qE '^root:.*:0:0:'; then
    record_poc double_encoded_traversal_rejected 0 "double-encoded traversal returned /etc/passwd (${STATUS}) - 2.4.50 bypass is live"
else
    record_poc double_encoded_traversal_rejected 1 "double-encoded traversal rejected (${STATUS:-no-response})"
fi

if http_get "/" | head -1 | grep -q ' 200'; then
    record_reg httpd_root_200_after_probe 1
else
    record_reg httpd_root_200_after_probe 0 "httpd not responding 200 on port 80"
fi

verify_finish
