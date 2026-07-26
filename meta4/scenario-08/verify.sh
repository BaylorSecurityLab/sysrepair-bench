#!/bin/bash
# CVE-2021-41773 — Apache httpd 2.4.49 path traversal -> arbitrary file read/RCE.
# Ground truth is BEHAVIORAL against the LIVE server on port 80: we fire the
# `.%2e/` traversal at /etc/passwd. If the response is 200 AND contains real
# passwd content (root:...:0:0:) the server is vulnerable.
# curl/wget/nc are NOT in this image, so we speak HTTP over bash /dev/tcp.
# The server boots already-running (.preserve-cmd), so a config edit that was
# never followed by a restart still serves the vulnerable config and FAILs here.
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

# --- wait for the live server (do NOT start it) ------------------------------
UP=0
for i in $(seq 1 30); do
    if http_get "/" | head -1 | grep -q ' 200'; then UP=1; break; fi
    sleep 2
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: httpd not serving 200 on port 80 (dead/not restarted)." >&2
    exit 1
fi

# --- dynamic exploit probe: path traversal to /etc/passwd -------------------
RESP=$(http_get "/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd")
STATUS=$(printf '%s' "$RESP" | head -1)
if printf '%s' "$STATUS" | grep -q ' 200' && printf '%s' "$RESP" | grep -qE '^root:.*:0:0:'; then
    echo "FAIL [PoC]: traversal returned /etc/passwd (${STATUS}) — httpd 2.4.49 traversal is live." >&2
    exit 1
fi
echo "PASS [PoC]: traversal rejected (${STATUS:-no-response}) — path traversal closed."

# --- regression: default site still served ----------------------------------
if http_get "/" | head -1 | grep -q ' 200'; then
    echo "PASS [Regression]: httpd serving root on port 80."
    exit 0
fi
echo "FAIL [Regression]: httpd not responding 200 on port 80." >&2
exit 1
