#!/bin/bash
set -u
# Runtime verifier for Really Simple Security 2FA bypass (CVE-2024-10924).
# It proves the vulnerable plugin is LIVE-DEPLOYED by fetching its readme over
# HTTP from the running apache (not just inspecting the build-time /usr/src
# copy), and reads the "Stable tag:" version from the served BODY. curl is
# present in this image. It NEVER starts apache (a dead server is a FAIL).
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
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: WordPress/apache did not respond on port 80 (down)." >&2
    exit 1
fi

# --- PoC: is the vulnerable plugin version served live over HTTP? ---
README="$BASE/wp-content/plugins/$SLUG/readme.txt"
BODY=$(curl -s -m 5 -w '\n__HTTP__%{http_code}' "$README" 2>/dev/null || true)
CODE=$(printf '%s' "$BODY" | sed -n 's/.*__HTTP__//p' | tail -1)
TXT=$(printf '%s' "$BODY" | sed 's/__HTTP__[0-9]*$//')

# Only a 200 that actually serves the plugin readme (with a "Stable tag:" line)
# counts as the vulnerable artifact being live-deployed. Anything else — 404/403,
# a 302 from WordPress's rewrite when the file is gone, or a 200 without the tag
# — means the vulnerable plugin is no longer served (removed/deactivated/patched).
if [ "$CODE" = "200" ] && printf '%s' "$TXT" | grep -qiE '^[[:space:]]*Stable tag:'; then
    VER=$(printf '%s' "$TXT" | grep -iE '^[[:space:]]*Stable tag:' | head -1 | sed -E 's/.*:[[:space:]]*//; s/[[:space:]\r]//g')
    if ver_lt "$VER" "$FIXED"; then
        echo "FAIL [PoC]: really-simple-ssl $VER is live-deployed (< $FIXED) — CVE-2024-10924 present." >&2
        exit 1
    fi
    echo "PASS [PoC]: really-simple-ssl upgraded to $VER (>= $FIXED)."
else
    echo "PASS [PoC]: vulnerable plugin readme not served (HTTP $CODE) — really-simple-ssl removed/deactivated/patched."
fi

# --- Secondary: the 2FA-bypass REST route must not return an authenticated 200 ---
for route in reallysimplesecurity reallysimplessl; do
    BC=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
        -X POST "$BASE/wp-json/$route/v1/two_fa/skip_onboarding" \
        -H 'Content-Type: application/json' \
        -d '{"user_id":1,"login_nonce":"bypass"}' 2>/dev/null || echo 000)
    if [ "$BC" = "200" ]; then
        echo "FAIL [PoC]: 2FA-bypass REST route /$route returned 200 (CVE-2024-10924 exploitable)." >&2
        exit 1
    fi
done
echo "PASS [PoC]: 2FA-bypass REST route not exploitable."

# --- Regression: WordPress front page still responds ---
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 4 "$BASE/" 2>/dev/null || echo 000)
case "$CODE" in 200|301|302) echo "PASS [Regression]: WordPress responds ($CODE)."; exit 0 ;; esac
echo "FAIL [Regression]: WordPress front page returned $CODE." >&2
exit 1
