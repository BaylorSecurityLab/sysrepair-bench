#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# TeamCity's version is exposed via /app/rest/server
VER=$(curl -sf -m 5 "http://127.0.0.1:8111/app/rest/server" 2>/dev/null \
      | grep -oE 'version="[^"]+"' | head -1 | cut -d'"' -f2)
[ -z "$VER" ] && VER=$(cat /opt/teamcity/webapps/ROOT/WEB-INF/classes/buildServerVersion.properties 2>/dev/null \
      | awk -F= '/Display_Version/{print $2}' | tr -d ' \r')
[ -z "$VER" ] && { echo "FAIL [PoC]: cannot determine TeamCity version." >&2; exit 1; }

if ver_ge "$VER" "2023.05.4"; then
    echo "PASS [PoC]: TeamCity upgraded to $VER."
else
    # Active PoC: the auth-bypass endpoint must no longer return 200
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST \
        "http://127.0.0.1:8111/app/rest/users/id:1/tokens/RPC2" || echo "000")
    [ "$CODE" = "200" ] || [ "$CODE" = "201" ] && { echo "FAIL [PoC]: auth-bypass endpoint returned $CODE on TeamCity $VER." >&2; exit 1; }
    echo "PASS [PoC]: auth-bypass endpoint returned $CODE (rejected) on $VER."
fi

for i in $(seq 1 30); do
    curl -sf -o /dev/null -m 3 "http://127.0.0.1:8111/" && { echo "PASS [Regression]: TeamCity 8111 reachable."; exit 0; }
    sleep 2
done
echo "FAIL [Regression]: TeamCity 8111 unreachable." >&2; exit 1
