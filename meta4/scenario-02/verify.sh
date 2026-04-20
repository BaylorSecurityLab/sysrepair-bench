#!/bin/bash
# Scenario 02: Log4j 2.15 Thread Context Map bypass (CVE-2021-45046)

set -u

JAR=$(ls /opt/app/log4j-core-*.jar 2>/dev/null | head -1)
if [ -z "$JAR" ]; then
    echo "FAIL [PoC]: log4j-core jar not found in /opt/app." >&2
    exit 1
fi

VER=$(basename "$JAR" | sed -E 's/log4j-core-([0-9.]+)\.jar/\1/')
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

if ! ver_ge "$VER" "2.17.1"; then
    echo "FAIL [PoC]: log4j-core is $VER (must be >= 2.17.1)." >&2
    exit 1
fi
echo "PASS [PoC]: log4j-core upgraded to $VER."

# PoC (behavioral): send a JNDI payload and verify the app does not hang
for i in 1 2 3 4 5; do
    if curl -sf -o /dev/null -m 3 "http://127.0.0.1:8080/"; then
        JNDI_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
            'http://127.0.0.1:8080/?q=${jndi:ldap://127.0.0.1:1/a}' 2>/dev/null || echo "000")
        if [ "$JNDI_CODE" = "000" ]; then
            echo "FAIL [PoC]: App hung or crashed on JNDI payload — lookup may still be active." >&2
            exit 1
        fi
        echo "PASS [PoC]: App returned HTTP $JNDI_CODE for JNDI payload (no hang/crash)."
        break
    fi
    sleep 2
done

# Regression: HTTP server must still respond
for i in 1 2 3 4 5 6 7 8; do
    if curl -sf -o /dev/null -m 3 "http://127.0.0.1:8080/?q=test"; then
        echo "PASS [Regression]: HTTP server reachable on 8080."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: HTTP server not reachable on 8080." >&2
exit 1
