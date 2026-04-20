#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# Confluence version lives in confluence-project.properties inside the WEB-INF
VER=$(find /opt/atlassian/confluence -maxdepth 5 -name 'confluence-project.properties' 2>/dev/null | head -1 | xargs -r awk -F= '/^version=/{print $2}')
[ -z "$VER" ] && VER=$(find /opt/atlassian/confluence -maxdepth 5 -name 'build.properties' 2>/dev/null | head -1 | xargs -r awk -F= '/version/{gsub(/[ \r]/,"",$2);print $2;exit}')
[ -z "$VER" ] && { echo "FAIL [PoC]: cannot read Confluence version." >&2; exit 1; }

SAFE=0
case "$VER" in
    7.18.*) ver_ge "$VER" "7.18.1" && SAFE=1 ;;
    7.4.*)  ver_ge "$VER" "7.4.17" && SAFE=1 ;;
    *) ver_ge "$VER" "7.18.1" && SAFE=1 ;;
esac

if [ "$SAFE" = "1" ]; then
    echo "PASS [PoC]: Confluence upgraded to $VER."
else
    echo "FAIL [PoC]: Confluence $VER vulnerable to CVE-2022-26134." >&2
    exit 1
fi

# PoC (behavioral): attempt OGNL injection via URL — must not execute
for i in $(seq 1 30); do
    if curl -sf -o /dev/null -m 5 "http://127.0.0.1:8090/"; then
        OGNL_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
            'http://127.0.0.1:8090/%24%7B1337*1337%7D/' 2>/dev/null || echo "000")
        OGNL_BODY=$(curl -s -m 5 \
            'http://127.0.0.1:8090/%24%7B1337*1337%7D/' 2>/dev/null || true)
        if echo "$OGNL_BODY" | grep -q '1787569'; then
            echo "FAIL [PoC]: OGNL injection returned computed value 1787569 — CVE-2022-26134 exploitable." >&2
            exit 1
        fi
        echo "PASS [PoC]: OGNL injection did not execute (HTTP $OGNL_CODE)."
        break
    fi
    sleep 5
done

for i in $(seq 1 60); do
    curl -sf -o /dev/null -m 3 "http://127.0.0.1:8090/" && { echo "PASS [Regression]: Confluence UI reachable on 8090."; exit 0; }
    sleep 5
done
echo "FAIL [Regression]: Confluence UI unreachable." >&2; exit 1
