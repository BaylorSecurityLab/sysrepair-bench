#!/bin/bash
# CVE-2021-41773 — Apache httpd 2.4.49 path traversal -> arbitrary file read/RCE.
# Ground truth is BEHAVIORAL against the LIVE server on port 80: we fire the
# `.%2e/` traversal at /etc/passwd. If the response is 200 AND contains real
# passwd content (root:...:0:0:) the server is vulnerable.
# curl/wget/nc are NOT in this image, so we speak HTTP over bash /dev/tcp.
# The server boots already-running (.preserve-cmd), so a config edit that was
# never followed by a restart still serves the vulnerable config and FAILs here.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "traversal refused because httpd is dead" is reported as regression_pass=false
# rather than collapsing into a bare exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1; PORT=80

http_get() { # $1=path -> raw response on stdout
    timeout 6 bash -c '
        exec 3<>/dev/tcp/'"$HOST"'/'"$PORT"' || exit 1
        printf "GET %s HTTP/1.0\r\nHost: x\r\nConnection: close\r\n\r\n" "$1" >&3
        cat <&3
        exec 3<&-
    ' _ "$1" 2>/dev/null || true
}

# --- wait for the live server (do NOT start it) ------------------------------
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

# --- dynamic exploit probe: path traversal to /etc/passwd -------------------
RESP=$(http_get "/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd")
STATUS=$(printf '%s' "$RESP" | head -1)
if printf '%s' "$STATUS" | grep -q ' 200' && printf '%s' "$RESP" | grep -qE '^root:.*:0:0:'; then
    record_poc path_traversal_rejected 0 "traversal returned /etc/passwd (${STATUS}) - httpd 2.4.49 traversal is live"
else
    record_poc path_traversal_rejected 1 "traversal rejected (${STATUS:-no-response})"
fi

# --- regression: default site still served ----------------------------------
if http_get "/" | head -1 | grep -q ' 200'; then
    record_reg httpd_root_200_after_probe 1
else
    record_reg httpd_root_200_after_probe 0 "httpd not responding 200 on port 80"
fi

verify_finish
