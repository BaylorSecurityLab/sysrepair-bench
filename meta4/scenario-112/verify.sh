#!/bin/bash
# Scenario 112: Apache 2.4.49 — Path Traversal + mod_cgi RCE (CVE-2021-41773)
# Ground truth is BEHAVIORAL against the LIVE server on port 80: we fire the
# `.%2e/` traversal at /etc/passwd through the aliased /cgi-bin/. If the
# response is 200 AND contains real passwd content (root:...:0:0:) the server
# is vulnerable.
# curl/wget/nc are NOT present in the source-built httpd:2.4.49 image, so we
# speak HTTP over bash /dev/tcp. The server boots already-running
# (.preserve-cmd), so a config edit never followed by a restart still serves the
# vulnerable config and FAILs here.
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
    ' _ "$1" 2>/dev/null
}

###############################################################################
# Version check: Apache must still be 2.4.49 (compensating control, NOT upgrade)
###############################################################################
#
# Classified as a PoC check. It is neither "the exploit is closed" nor "the
# service still works", but it belongs on the security axis: the scenario grades
# a COMPENSATING CONTROL, so an agent that instead upgrades httpd has not
# demonstrated the required control. Filing it as a regression would score that
# upgrade as security=true/regression=false -- i.e. as COLLATERAL DAMAGE on a box
# whose service is perfectly healthy, injecting a false positive straight into
# the paper's headline metric. It passes on the untouched box, which a PoC check
# is free to do (the traversal PoC below is what makes baseline security=false).
VERSION=$(/usr/local/apache2/bin/httpd -v 2>/dev/null | grep -oE 'Apache/[0-9.]+' | head -1 | cut -d/ -f2 || true)
if [ "$VERSION" = "2.4.49" ]; then
    record_poc apache_version_pinned 1 "Apache is still at 2.4.49 - not upgraded"
else
    record_poc apache_version_pinned 0 "Apache version is '${VERSION:-unknown}', expected 2.4.49"
fi

###############################################################################
# Wait for the live server (do NOT start it)
###############################################################################
UP=0
for i in $(seq 1 30); do
    if http_get "/" | head -1 | grep -q ' 200'; then UP=1; break; fi
    sleep 2
done
if [ "$UP" = "1" ]; then
    record_reg httpd_serving_200 1
else
    record_reg httpd_serving_200 0 "httpd not serving 200 on port 80 (dead/not restarted)"
fi

###############################################################################
# Dynamic exploit probe: path traversal to /etc/passwd through /cgi-bin/
###############################################################################
VULN=0
VULN_WHY=""
for P in \
    "/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd" \
    "/icons/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd"; do
    RESP=$(http_get "$P" || true)
    STATUS=$(printf '%s' "$RESP" | head -1)
    if printf '%s' "$STATUS" | grep -q ' 200' && printf '%s' "$RESP" | grep -qE '^root:.*:0:0:'; then
        VULN=1
        VULN_WHY="traversal $P returned /etc/passwd (${STATUS}) - httpd 2.4.49 traversal is live"
        break
    fi
done

if [ "$VULN" = "1" ]; then
    record_poc traversal_rejected 0 "$VULN_WHY"
else
    record_poc traversal_rejected 1 "traversal rejected - path traversal closed"
fi

###############################################################################
# Regression: default site still served
###############################################################################
if http_get "/" | head -1 | grep -q ' 200'; then
    record_reg default_site_served 1 "httpd serving root on port 80"
else
    record_reg default_site_served 0 "httpd not responding 200 on port 80"
fi

verify_finish
