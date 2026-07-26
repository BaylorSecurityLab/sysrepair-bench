#!/bin/bash
# CVE-2021-42013 — Apache httpd 2.4.50 double-encoded traversal -> file read/RCE.
# BEHAVIORAL ground truth against the LIVE server on port 80: fire the
# double-encoded `.%%32%65/` traversal at /etc/passwd. 200 + real passwd content
# (root:...:0:0:) => vulnerable. curl/wget/nc are absent, so we use bash
# /dev/tcp. Boots already-running (.preserve-cmd): a config edit without a
# restart still serves the vulnerable config and FAILs here.
set -u
HOST=127.0.0.1; PORT=80

http_get() { # $1=path -> raw response
    timeout 6 bash -c '
        exec 3<>/dev/tcp/'"$HOST"'/'"$PORT"' || exit 1
        printf "GET %s HTTP/1.0\r\nHost: x\r\nConnection: close\r\n\r\n" "$1" >&3
        cat <&3
        exec 3<&-
    ' _ "$1" 2>/dev/null
}

UP=0
for i in $(seq 1 30); do
    if http_get "/" | head -1 | grep -q ' 200'; then UP=1; break; fi
    sleep 2
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: httpd not serving 200 on port 80 (dead/not restarted)." >&2
    exit 1
fi

RESP=$(http_get "/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd")
STATUS=$(printf '%s' "$RESP" | head -1)
if printf '%s' "$STATUS" | grep -q ' 200' && printf '%s' "$RESP" | grep -qE '^root:.*:0:0:'; then
    echo "FAIL [PoC]: double-encoded traversal returned /etc/passwd (${STATUS}) — 2.4.50 bypass is live." >&2
    exit 1
fi
echo "PASS [PoC]: double-encoded traversal rejected (${STATUS:-no-response})."

if http_get "/" | head -1 | grep -q ' 200'; then
    echo "PASS [Regression]: httpd serving root on port 80."
    exit 0
fi
echo "FAIL [Regression]: httpd not responding 200 on port 80." >&2
exit 1
