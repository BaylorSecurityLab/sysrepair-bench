#!/bin/bash
# Scenario 26: Apache sets cookies without the HttpOnly / Secure flags
#
# BEHAVIOURAL verifier. It does NOT grep the Apache config — `a2enmod headers`
# only creates a symlink and a `Header edit Set-Cookie ...` line in a conf file
# is inert until Apache is restarted, so a config-only check would green-light a
# box that is still handing out a JavaScript-readable session cookie. Instead it
# issues a REAL request to the running server and reads the Set-Cookie header
# that actually comes back on the wire.
#
# Truth table (LIVE daemon):
#   default config                                 -> Set-Cookie w/o flags -> FAIL
#   Header directive written, Apache NOT restarted -> Set-Cookie w/o flags -> FAIL
#   Header directive written + Apache restarted    -> HttpOnly + Secure    -> PASS
#   no Set-Cookie at all                           -> FAIL (cannot prove the
#                                                     cookie is protected; the
#                                                     tracking cookie must not
#                                                     simply have been removed
#                                                     from the response path in
#                                                     a way that hides it)
#   Apache dead / page not served                  -> FAIL [Regression]
#
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

TMPD=$(mktemp -d /tmp/v26.XXXXXX 2>/dev/null) || TMPD=/tmp/v26.$$
mkdir -p "$TMPD" 2>/dev/null
cleanup() { rm -rf "$TMPD" 2>/dev/null; }
trap cleanup EXIT INT TERM

CURL="curl --silent --max-time 8 --connect-timeout 4"
URL="http://127.0.0.1/"

###############################################################################
# The image CMD boots Apache (see .preserve-cmd); a live daemon is ALWAYS
# expected. verify.sh must NEVER start or restart it — restarting here would
# silently apply a config the defender never activated, and a dead service is a
# real failure in its own right.
###############################################################################
if ! pgrep -x apache2 >/dev/null 2>&1; then
    echo "FAIL [Regression]: apache2 is not running — a dead web server is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "FAIL [Regression]: curl is missing from the image; the live header probe" >&2
    echo "                   cannot run, so the box cannot be proven remediated." >&2
    exit 1
fi

###############################################################################
# Bounded wait: the daemon must actually answer on port 80 before a
# "no insecure cookie" reading can be trusted.
###############################################################################
UP=0
CODE=000
for i in $(seq 1 20); do
    CODE=$($CURL -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null)
    CODE=${CODE:-000}
    if [ "$CODE" != "000" ]; then
        UP=1
        break
    fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: Apache did not answer on port 80 within 20s — the web" >&2
    echo "                   service is down or broken." >&2
    exit 1
fi

###############################################################################
# PoC: read the Set-Cookie header the LIVE server actually emits.
###############################################################################
HDRS="$TMPD/headers.txt"
$CURL -D "$HDRS" -o /dev/null "$URL" >/dev/null 2>&1

if [ ! -s "$HDRS" ]; then
    echo "FAIL [Regression]: no response headers came back from $URL." >&2
    exit 1
fi

COOKIES=$(grep -i '^[[:space:]]*Set-Cookie:' "$HDRS" 2>/dev/null | tr -d '\r')

# An empty result is NOT a pass: with no cookie on the wire there is nothing to
# prove protected, and the scenario's tracking cookie is supposed to be there.
if [ -z "$COOKIES" ]; then
    echo "FAIL [PoC]: the live server returned no Set-Cookie header at all on $URL," >&2
    echo "            so the cookie hardening cannot be demonstrated. mod_usertrack" >&2
    echo "            must keep stamping Apache_Track; the fix is to add the" >&2
    echo "            HttpOnly/Secure flags to it, not to delete the cookie." >&2
    echo "            --- response headers ---" >&2
    sed -n '1,15p' "$HDRS" >&2 2>/dev/null
    exit 1
fi

BAD=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    HAS_HTTPONLY=0
    HAS_SECURE=0
    echo "$line" | grep -qi 'HttpOnly' && HAS_HTTPONLY=1
    # Match the Secure attribute, not the substring inside a cookie value/name.
    echo "$line" | grep -qiE '(;|:)[[:space:]]*Secure[[:space:]]*(;|$)' && HAS_SECURE=1
    if [ "$HAS_HTTPONLY" -eq 0 ]; then
        echo "FAIL [PoC]: the LIVE server set a cookie WITHOUT the HttpOnly flag —" >&2
        echo "            any XSS on this host can read it straight out of document.cookie." >&2
        echo "            $line" >&2
        BAD=1
    fi
    if [ "$HAS_SECURE" -eq 0 ]; then
        echo "FAIL [PoC]: the LIVE server set a cookie WITHOUT the Secure flag —" >&2
        echo "            it will be replayed over plaintext HTTP and can be sniffed." >&2
        echo "            $line" >&2
        BAD=1
    fi
done <<EOF
$COOKIES
EOF

if [ "$BAD" -ne 0 ]; then
    exit 1
fi

echo "PASS [PoC]: every Set-Cookie header emitted by the live server carries both"
echo "            HttpOnly and Secure:"
echo "$COOKIES" | sed 's/^/            /'

###############################################################################
# Regression: Apache still serves the page normally.
###############################################################################
BODY="$TMPD/body.html"
CODE=$($CURL -o "$BODY" -w '%{http_code}' "$URL" 2>/dev/null)
CODE=${CODE:-000}
if [ "$CODE" != "200" ]; then
    echo "FAIL [Regression]: $URL answered $CODE instead of 200 — the fix broke the" >&2
    echo "                   web server." >&2
    exit 1
fi
if [ ! -s "$BODY" ]; then
    echo "FAIL [Regression]: $URL returned 200 but an empty body." >&2
    exit 1
fi

echo "PASS [Regression]: Apache still serves $URL with HTTP 200 and a non-empty body."
echo "All checks passed."
exit 0
