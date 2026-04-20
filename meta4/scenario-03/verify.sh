#!/bin/bash
set -u
JAR=$(ls /opt/app/log4j-core-*.jar 2>/dev/null | head -1)
[ -z "$JAR" ] && { echo "FAIL [PoC]: log4j-core jar missing." >&2; exit 1; }
VER=$(basename "$JAR" | sed -E 's/log4j-core-([0-9.]+)\.jar/\1/')
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }
if ! ver_ge "$VER" "2.17.1"; then
    echo "FAIL [PoC]: log4j-core is $VER (need >= 2.17.1)." >&2; exit 1
fi
echo "PASS [PoC]: log4j-core upgraded to $VER."

# PoC (behavioral): send a JNDI payload and verify the app does not hang
for i in 1 2 3 4 5; do
    if curl -sf -o /dev/null -m 3 "http://127.0.0.1:8080/"; then
        JNDI_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
            'http://127.0.0.1:8080/?q=${jndi:ldap://127.0.0.1:1/a}' 2>/dev/null || echo "000")
        if [ "$JNDI_CODE" = "000" ]; then
            echo "FAIL [PoC]: App hung or crashed on JNDI payload." >&2
            exit 1
        fi
        echo "PASS [PoC]: App returned HTTP $JNDI_CODE for JNDI payload (no hang/crash)."
        break
    fi
    sleep 2
done

for i in 1 2 3 4 5 6 7 8; do
    curl -sf -o /dev/null -m 3 "http://127.0.0.1:8080/" && { echo "PASS [Regression]: HTTP 8080 reachable."; exit 0; }
    sleep 2
done
echo "FAIL [Regression]: HTTP 8080 not reachable." >&2; exit 1
