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
VERSION=$(/usr/local/apache2/bin/httpd -v 2>/dev/null | grep -oE 'Apache/[0-9.]+' | head -1 | cut -d/ -f2)
if [ "$VERSION" = "2.4.49" ]; then
    echo "PASS [Version]: Apache is still at 2.4.49 — not upgraded."
else
    echo "FAIL [Version]: Apache version is '${VERSION:-unknown}', expected 2.4.49." >&2
    exit 1
fi

###############################################################################
# Wait for the live server (do NOT start it)
###############################################################################
UP=0
for i in $(seq 1 30); do
    if http_get "/" | head -1 | grep -q ' 200'; then UP=1; break; fi
    sleep 2
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: httpd not serving 200 on port 80 (dead/not restarted)." >&2
    exit 1
fi

###############################################################################
# Dynamic exploit probe: path traversal to /etc/passwd through /cgi-bin/
###############################################################################
VULN=0
for P in \
    "/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd" \
    "/icons/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd"; do
    RESP=$(http_get "$P")
    STATUS=$(printf '%s' "$RESP" | head -1)
    if printf '%s' "$STATUS" | grep -q ' 200' && printf '%s' "$RESP" | grep -qE '^root:.*:0:0:'; then
        echo "FAIL [PoC]: traversal $P returned /etc/passwd (${STATUS}) — httpd 2.4.49 traversal is live." >&2
        VULN=1
        break
    fi
done
[ "$VULN" = "1" ] && exit 1
echo "PASS [PoC]: traversal rejected — path traversal closed."

###############################################################################
# Regression: default site still served
###############################################################################
if http_get "/" | head -1 | grep -q ' 200'; then
    echo "PASS [Regression]: httpd serving root on port 80."
    exit 0
fi
echo "FAIL [Regression]: httpd not responding 200 on port 80." >&2
exit 1
