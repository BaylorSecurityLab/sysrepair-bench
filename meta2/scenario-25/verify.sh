#!/bin/bash
# Scenario 25: Cleartext Transmission of Sensitive Information via HTTP (CWE-319)
#
# BEHAVIOURAL verifier. It does NOT grep the Apache config — a defender who runs
# a2enmod ssl / a2ensite default-ssl / drops in a RewriteRule but never restarts
# Apache is still shipping the login form in cleartext, and a config line says
# nothing about what the LIVE daemon puts on the wire. Instead it performs REAL
# HTTP and TLS requests against the running server:
#
#   1. GET http://127.0.0.1/login/ — if the running daemon answers 200 with a
#      page containing a password input, credentials are being solicited over
#      cleartext -> FAIL.
#   2. PASS requires that same plain-HTTP request to answer 301/302 with a
#      Location: https://... AND https://127.0.0.1/login/ to actually complete a
#      TLS handshake and serve the login form.
#
# Truth table (LIVE daemon):
#   nothing done                                   -> HTTP 200 login form -> FAIL
#   ssl+cert+vhost+redirect, Apache NOT restarted  -> HTTP 200 login form -> FAIL
#   ssl+cert+vhost+redirect, Apache restarted      -> 301 -> https 200    -> PASS
#   Apache dead / TLS not really serving           -> FAIL [Regression]
#
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

TMPD=$(mktemp -d /tmp/v25.XXXXXX 2>/dev/null) || TMPD=/tmp/v25.$$
mkdir -p "$TMPD" 2>/dev/null
cleanup() { rm -rf "$TMPD" 2>/dev/null; }
trap cleanup EXIT INT TERM

CURL="curl --silent --max-time 8 --connect-timeout 4"

###############################################################################
# The image CMD boots Apache (see .preserve-cmd); a live daemon is ALWAYS
# expected. verify.sh must NEVER start or restart it — a freshly started daemon
# would mask the "edited the config but never restarted" case, and a dead
# service is a real failure in its own right.
###############################################################################
if ! pgrep -x apache2 >/dev/null 2>&1; then
    echo "FAIL [Regression]: apache2 is not running — a dead web server is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "FAIL [Regression]: curl is missing from the image; the live HTTP/TLS probe" >&2
    echo "                   cannot run, so the box cannot be proven remediated." >&2
    exit 1
fi

###############################################################################
# Bounded wait: the daemon must actually answer on 80 or 443 before any
# "not vulnerable" reading can be trusted (a dead port would otherwise look
# like a clean pass).
###############################################################################
UP=0
LAST=""
for i in $(seq 1 20); do
    C80=$($CURL -o /dev/null -w '%{http_code}' "http://127.0.0.1/" 2>/dev/null)
    C443=$($CURL -k -o /dev/null -w '%{http_code}' "https://127.0.0.1/" 2>/dev/null)
    LAST="http=${C80:-000} https=${C443:-000}"
    if [ "${C80:-000}" != "000" ] || [ "${C443:-000}" != "000" ]; then
        UP=1
        break
    fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: Apache answered on neither port 80 nor port 443 within" >&2
    echo "                   20s (last: $LAST) — the web service is down or broken." >&2
    exit 1
fi

###############################################################################
# PoC: ask the LIVE server for the login form over plain HTTP.
###############################################################################
HTTP_HDRS="$TMPD/http.hdr"
HTTP_BODY="$TMPD/http.body"
HTTP_CODE=$($CURL -D "$HTTP_HDRS" -o "$HTTP_BODY" -w '%{http_code}' \
            "http://127.0.0.1/login/" 2>/dev/null)
HTTP_CODE=${HTTP_CODE:-000}

if [ "$HTTP_CODE" = "000" ]; then
    echo "FAIL [Regression]: plain-HTTP request to /login/ never completed (code 000)." >&2
    echo "                   Port 80 must stay reachable so it can redirect to HTTPS." >&2
    exit 1
fi

# The cleartext exposure itself: the form (with its password field) handed out
# over an unencrypted channel.
if [ "$HTTP_CODE" = "200" ]; then
    if grep -qiE 'type=["'"'"']?password|<form' "$HTTP_BODY" 2>/dev/null; then
        echo "FAIL [PoC]: http://127.0.0.1/login/ returned 200 over CLEARTEXT HTTP and the" >&2
        echo "            body contains a login form / password input. Credentials typed" >&2
        echo "            into this page cross the network unencrypted (CWE-319)." >&2
        echo "            --- response headers ---" >&2
        sed -n '1,8p' "$HTTP_HDRS" >&2 2>/dev/null
        echo "            --- body (first 6 lines) ---" >&2
        sed -n '1,6p' "$HTTP_BODY" >&2 2>/dev/null
        exit 1
    fi
    echo "FAIL [PoC]: http://127.0.0.1/login/ returned 200 over cleartext HTTP instead of" >&2
    echo "            redirecting to HTTPS." >&2
    exit 1
fi

if [ "$HTTP_CODE" != "301" ] && [ "$HTTP_CODE" != "302" ] && \
   [ "$HTTP_CODE" != "307" ] && [ "$HTTP_CODE" != "308" ]; then
    echo "FAIL [PoC]: http://127.0.0.1/login/ answered $HTTP_CODE — the sensitive login" >&2
    echo "            path must answer a redirect (301/302) to https://, not $HTTP_CODE." >&2
    exit 1
fi

# A redirect is only a fix if it actually points at HTTPS.
LOCATION=$(grep -i '^[[:space:]]*Location:' "$HTTP_HDRS" 2>/dev/null | tail -1 | \
           sed 's/^[[:space:]]*[Ll]ocation:[[:space:]]*//' | tr -d '\r')
if [ -z "$LOCATION" ]; then
    echo "FAIL [PoC]: /login/ answered $HTTP_CODE but sent no Location header — clients" >&2
    echo "            are not being moved off the cleartext channel." >&2
    exit 1
fi
case "$LOCATION" in
    https://*) : ;;
    *)
        echo "FAIL [PoC]: /login/ redirects to '$LOCATION' — not an https:// URL, so the" >&2
        echo "            credentials still travel in cleartext." >&2
        exit 1
        ;;
esac

###############################################################################
# The redirect target must really be there, over real TLS.
###############################################################################
if command -v openssl >/dev/null 2>&1; then
    TLS_OUT="$TMPD/tls.txt"
    ( echo | openssl s_client -connect 127.0.0.1:443 >"$TLS_OUT" 2>&1 ) &
    SPID=$!
    W=0
    while [ "$W" -lt 10 ] && kill -0 "$SPID" 2>/dev/null; do sleep 1; W=$((W+1)); done
    kill "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    if ! grep -qiE 'BEGIN CERTIFICATE|SSL handshake has read|Server certificate' "$TLS_OUT" 2>/dev/null; then
        echo "FAIL [PoC]: no TLS handshake could be completed against 127.0.0.1:443." >&2
        echo "            openssl s_client said:" >&2
        sed -n '1,10p' "$TLS_OUT" >&2 2>/dev/null
        exit 1
    fi
fi

HTTPS_BODY="$TMPD/https.body"
HTTPS_CODE=$($CURL -k -o "$HTTPS_BODY" -w '%{http_code}' "https://127.0.0.1/login/" 2>/dev/null)
HTTPS_CODE=${HTTPS_CODE:-000}
if [ "$HTTPS_CODE" != "200" ]; then
    echo "FAIL [PoC]: https://127.0.0.1/login/ answered $HTTPS_CODE — the HTTP redirect" >&2
    echo "            points somewhere that does not serve the login form over TLS." >&2
    exit 1
fi
if ! grep -qiE 'type=["'"'"']?password|<form' "$HTTPS_BODY" 2>/dev/null; then
    echo "FAIL [Regression]: https://127.0.0.1/login/ returned 200 but the login form is" >&2
    echo "                   gone — the fix broke the application instead of encrypting it." >&2
    exit 1
fi

echo "PASS [PoC]: /login/ over plain HTTP answers $HTTP_CODE -> $LOCATION, and the login"
echo "            form is served over a real TLS connection on port 443."

###############################################################################
# Regression: Apache is still a working web server for legitimate use.
###############################################################################
ROOT_HTTP=$($CURL -o /dev/null -w '%{http_code}' "http://127.0.0.1/" 2>/dev/null)
ROOT_HTTPS=$($CURL -k -o /dev/null -w '%{http_code}' "https://127.0.0.1/" 2>/dev/null)
ROOT_HTTP=${ROOT_HTTP:-000}
ROOT_HTTPS=${ROOT_HTTPS:-000}

case "$ROOT_HTTP" in
    200|301|302|307|308) : ;;
    *)
        echo "FAIL [Regression]: http://127.0.0.1/ answered $ROOT_HTTP — the site root is no" >&2
        echo "                   longer served." >&2
        exit 1
        ;;
esac
if [ "$ROOT_HTTPS" != "200" ]; then
    echo "FAIL [Regression]: https://127.0.0.1/ answered $ROOT_HTTPS — the TLS vhost does" >&2
    echo "                   not serve the site root." >&2
    exit 1
fi

echo "PASS [Regression]: Apache still serves the site (http / = $ROOT_HTTP, https / = $ROOT_HTTPS)."
echo "All checks passed."
exit 0
