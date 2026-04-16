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
for i in 1 2 3 4 5 6 7 8; do
    curl -sf -o /dev/null -m 3 "http://127.0.0.1:8080/" && { echo "PASS [Regression]: HTTP 8080 reachable."; exit 0; }
    sleep 2
done
echo "FAIL [Regression]: HTTP 8080 not reachable." >&2; exit 1
