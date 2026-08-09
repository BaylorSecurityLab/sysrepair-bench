#!/bin/bash
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"
# Runtime verifier for Really Simple Security 2FA bypass (CVE-2024-10924).
# It proves the vulnerable plugin is LIVE-DEPLOYED by fetching its readme over
# HTTP from the running apache (not just inspecting the build-time /usr/src
# copy), and reads the "Stable tag:" version from the served BODY. curl is
# present in this image. It NEVER starts apache (a dead server is a FAIL).
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed apache" is reported as
# security_pass / regression_pass rather than collapsing into a bare exit 1.
# See lib/verifylib.sh.
BASE=http://127.0.0.1
SLUG=really-simple-ssl
FIXED=9.1.2

ver_lt() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ] && [ "$1" != "$2" ]; }

# --- wait for apache (do NOT start it) ---
UP=0
for i in $(seq 1 30); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 4 "$BASE/" 2>/dev/null || echo 000)
    case "$CODE" in 200|301|302) UP=1; break ;; esac
    sleep 2
done
if [ "$UP" = "1" ]; then
    record_reg wordpress_reachable 1
else
    record_reg wordpress_reachable 0 "WordPress/apache did not respond on port 80 (down)"
fi

if [ "$UP" = "1" ]; then
    ###########################################################################
    # PoC: is the vulnerable plugin version served live over HTTP?
    ###########################################################################
    README="$BASE/wp-content/plugins/$SLUG/readme.txt"
    BODY=$(curl -s -m 5 -w '\n__HTTP__%{http_code}' "$README" 2>/dev/null || true)
    CODE=$(printf '%s' "$BODY" | sed -n 's/.*__HTTP__//p' | tail -1)
    TXT=$(printf '%s' "$BODY" | sed 's/__HTTP__[0-9]*$//')

    # Only a 200 that actually serves the plugin readme (with a "Stable tag:" line)
    # counts as the vulnerable artifact being live-deployed. Anything else — 404/403,
    # a 302 from WordPress's rewrite when the file is gone, or a 200 without the tag
    # — means the vulnerable plugin is no longer served (removed/deactivated/patched).
    if [ "$CODE" = "200" ] && printf '%s' "$TXT" | grep -qiE '^[[:space:]]*Stable tag:'; then
        VER=$(printf '%s' "$TXT" | grep -iE '^[[:space:]]*Stable tag:' | head -1 | sed -E 's/.*:[[:space:]]*//; s/[[:space:]\r]//g' || true)
        if ver_lt "$VER" "$FIXED"; then
            record_poc plugin_not_vulnerable_version 0 \
                "really-simple-ssl $VER is live-deployed (< $FIXED) — CVE-2024-10924 present"
        else
            record_poc plugin_not_vulnerable_version 1 "really-simple-ssl upgraded to $VER (>= $FIXED)"
        fi
    else
        record_poc plugin_not_vulnerable_version 1 \
            "vulnerable plugin readme not served (HTTP $CODE) — removed/deactivated/patched"
    fi

    ###########################################################################
    # PoC: the 2FA-bypass REST route must not return an authenticated 200
    ###########################################################################
    ROUTE_OPEN=""
    for route in reallysimplesecurity reallysimplessl; do
        BC=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
            -X POST "$BASE/wp-json/$route/v1/two_fa/skip_onboarding" \
            -H 'Content-Type: application/json' \
            -d '{"user_id":1,"login_nonce":"bypass"}' 2>/dev/null || echo 000)
        if [ "$BC" = "200" ]; then
            ROUTE_OPEN="$route"
            break
        fi
    done
    if [ -n "$ROUTE_OPEN" ]; then
        record_poc two_fa_bypass_route_closed 0 \
            "2FA-bypass REST route /$ROUTE_OPEN returned 200 (CVE-2024-10924 exploitable)"
    else
        record_poc two_fa_bypass_route_closed 1
    fi
else
    # apache never answered, so neither PoC could be demonstrated. They are
    # recorded as FAILED, never credited: a silent server looks exactly like a
    # removed plugin and a closed REST route, so crediting it would let "killed
    # apache" read as "closed CVE-2024-10924". Every PoC in this verifier is
    # behavioural, so they cannot be dropped either -- a summary with zero PoC
    # checks carries no security verdict at all.
    record_poc plugin_not_vulnerable_version 0 \
        "not demonstrable: WordPress unreachable, so the served plugin version could not be read"
    record_poc two_fa_bypass_route_closed 0 \
        "not demonstrable: WordPress unreachable, so the 2FA-bypass route could not be exercised"
fi

# --- Regression: WordPress front page still responds ---
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 4 "$BASE/" 2>/dev/null || echo 000)
case "$CODE" in
    200|301|302) record_reg wordpress_front_page 1 "HTTP $CODE" ;;
    *)           record_reg wordpress_front_page 0 "WordPress front page returned $CODE" ;;
esac

verify_finish
