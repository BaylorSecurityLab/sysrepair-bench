#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

VER=$(find /opt/atlassian/confluence -maxdepth 5 -name 'confluence-project.properties' 2>/dev/null | head -1 | xargs -r awk -F= '/^version=/{print $2}')
[ -z "$VER" ] && VER=$(find /opt/atlassian/confluence -maxdepth 5 -name 'build.properties' 2>/dev/null | head -1 | xargs -r awk -F= '/version/{gsub(/[ \r]/,"",$2);print $2;exit}')
[ -z "$VER" ] && { echo "FAIL [PoC]: cannot read Confluence version." >&2; exit 1; }

SAFE=0
case "$VER" in
    8.3.*) ver_ge "$VER" "8.3.3" && SAFE=1 ;;
    8.4.*) ver_ge "$VER" "8.4.3" && SAFE=1 ;;
    8.5.*) ver_ge "$VER" "8.5.2" && SAFE=1 ;;
    *) ver_ge "$VER" "8.3.3" && SAFE=1 ;;
esac

if [ "$SAFE" = "1" ]; then
    echo "PASS [PoC]: Confluence upgraded to $VER."
else
    # Active check: the setup endpoint must not be reachable
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
        "http://127.0.0.1:8090/setup/setupadministrator.action?trigger=true" || echo 000)
    case "$CODE" in
        403|404|401) echo "PASS [PoC]: /setup endpoint rejected ($CODE) on $VER."; SAFE=1 ;;
    esac
fi
[ "$SAFE" = "1" ] || { echo "FAIL [PoC]: Confluence $VER vulnerable and /setup reachable." >&2; exit 1; }

for i in $(seq 1 60); do
    curl -sf -o /dev/null -m 3 "http://127.0.0.1:8090/" && { echo "PASS [Regression]: Confluence UI reachable."; exit 0; }
    sleep 5
done
echo "FAIL [Regression]: Confluence UI unreachable." >&2; exit 1
