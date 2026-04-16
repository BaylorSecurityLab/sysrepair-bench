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

for i in $(seq 1 60); do
    curl -sf -o /dev/null -m 3 "http://127.0.0.1:8090/" && { echo "PASS [Regression]: Confluence UI reachable on 8090."; exit 0; }
    sleep 5
done
echo "FAIL [Regression]: Confluence UI unreachable." >&2; exit 1
