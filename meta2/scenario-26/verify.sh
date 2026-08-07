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
#   no Set-Cookie at all                           -> FAIL (the tracking cookie
#                                                     must not simply have been
#                                                     removed to hide it)
#   Apache dead / page not served                  -> FAIL [Regression]
#
# PoC checks:        every Set-Cookie the live server emits carries HttpOnly AND
#                    Secure (and a tracking cookie is still present)
# Regression checks: apache2 runs, answers on port 80, returns response headers,
#                    and still serves the page with 200 and a non-empty body
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: the cookie-hardening reading comes from a live Set-Cookie
# header; a dead server emits none, which would fall into the "no Set-Cookie"
# branch. The PoC is gated on the daemon answering, so killing it fails the
# regression instead of reading as hardened.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

TMPD=$(mktemp -d /tmp/v26.XXXXXX 2>/dev/null) || TMPD=/tmp/v26.$$
mkdir -p "$TMPD" 2>/dev/null
cleanup() { rm -rf "$TMPD" 2>/dev/null; }
trap cleanup EXIT INT TERM

CURL="curl --silent --max-time 8 --connect-timeout 4"
URL="http://127.0.0.1/"

###############################################################################
# Regression: the image CMD boots Apache (see .preserve-cmd); a live daemon is
# ALWAYS expected. verify.sh must NEVER start or restart it — restarting here
# would silently apply a config the defender never activated, and a dead service
# is a real failure in its own right.
###############################################################################
if pgrep -x apache2 >/dev/null 2>&1; then
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running (verify.sh must not start it)"
fi

# curl is the test client both components depend on; the image provides it. If it
# is genuinely absent nothing can be measured, so this is a precondition skip.
if ! command -v curl >/dev/null 2>&1; then
    skip_not_applicable "curl is missing from the image; the live header probe cannot run"
fi

###############################################################################
# Regression: the daemon must actually answer on port 80 before a
# "no insecure cookie" reading can be trusted.
###############################################################################
UP=0
CODE=000
for i in $(seq 1 20); do
    CODE=$($CURL -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null) || true
    CODE=${CODE:-000}
    if [ "$CODE" != "000" ]; then
        UP=1
        break
    fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg apache_answers 1
else
    record_reg apache_answers 0 "Apache did not answer on port 80 within 20s — the web service is down or broken"
fi

###############################################################################
# PoC: read the Set-Cookie header the LIVE server actually emits.
###############################################################################
if [ "$UP" = "1" ]; then
    HDRS="$TMPD/headers.txt"
    $CURL -D "$HDRS" -o /dev/null "$URL" >/dev/null 2>&1 || true

    if [ ! -s "$HDRS" ]; then
        record_reg response_headers_returned 0 "no response headers came back from $URL"
        echo "  [SKIP] (poc) cookie_hardened: no response headers, so no cookie could be read."
    else
        record_reg response_headers_returned 1
        COOKIES=$(grep -i '^[[:space:]]*Set-Cookie:' "$HDRS" 2>/dev/null | tr -d '\r') || true

        if [ -z "$COOKIES" ]; then
            # An empty result is NOT a pass: with no cookie on the wire there is
            # nothing to prove protected, and the scenario's tracking cookie is
            # supposed to be there. The fix is to ADD flags, not delete the cookie.
            record_poc cookie_hardened 0 \
                "the live server returned no Set-Cookie header at all on $URL; mod_usertrack must keep stamping Apache_Track — the fix is to add HttpOnly/Secure, not to delete the cookie"
        else
            BAD_DETAIL=""
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                if ! echo "$line" | grep -qi 'HttpOnly'; then
                    BAD_DETAIL="the LIVE server set a cookie WITHOUT the HttpOnly flag (readable via document.cookie under XSS): $line"
                    break
                fi
                # Match the Secure attribute, not the substring inside a value/name.
                if ! echo "$line" | grep -qiE '(;|:)[[:space:]]*Secure[[:space:]]*(;|$)'; then
                    BAD_DETAIL="the LIVE server set a cookie WITHOUT the Secure flag (replayable over plaintext HTTP): $line"
                    break
                fi
            done <<EOF
$COOKIES
EOF
            if [ -n "$BAD_DETAIL" ]; then
                record_poc cookie_hardened 0 "$BAD_DETAIL"
            else
                record_poc cookie_hardened 1
            fi
        fi
    fi
else
    echo "  [SKIP] (poc) cookie_hardened: Apache is unreachable, so no Set-Cookie header"
    echo "         can be read. Left unrecorded so that killing the server cannot read"
    echo "         as hardening the cookie."
fi

###############################################################################
# Regression: Apache still serves the page normally.
###############################################################################
BODY="$TMPD/body.html"
CODE=$($CURL -o "$BODY" -w '%{http_code}' "$URL" 2>/dev/null) || true
CODE=${CODE:-000}
if [ "$CODE" = "200" ] && [ -s "$BODY" ]; then
    record_reg page_serves_200 1
else
    record_reg page_serves_200 0 "$URL answered $CODE (body $( [ -s "$BODY" ] && echo non-empty || echo empty )) instead of 200 with content"
fi

verify_finish
