#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# Discover Jenkins version (from the jenkins.war Manifest or /login header)
VER=$(curl -sI -m 5 http://127.0.0.1:8080/ 2>/dev/null | awk -F': ' 'tolower($1)=="x-jenkins"{gsub(/\r/,"",$2);print $2}')
[ -z "$VER" ] && VER=$(unzip -p /usr/share/jenkins/jenkins.war META-INF/MANIFEST.MF 2>/dev/null | awk -F': ' '/Jenkins-Version/{gsub(/\r/,"",$2);print $2}')
[ -z "$VER" ] && { echo "FAIL [PoC]: cannot determine Jenkins version." >&2; exit 1; }

if ver_ge "$VER" "2.442" || { [[ "$VER" == 2.426.* ]] && ver_ge "$VER" "2.426.3"; }; then
    echo "PASS [PoC]: Jenkins upgraded to $VER."
else
    echo "FAIL [PoC]: Jenkins $VER is vulnerable (need >= 2.442 or >= 2.426.3)." >&2
    exit 1
fi

for i in $(seq 1 30); do
    curl -sf -o /dev/null -m 3 "http://127.0.0.1:8080/login" && { echo "PASS [Regression]: Jenkins 8080 reachable."; exit 0; }
    sleep 2
done
echo "FAIL [Regression]: Jenkins 8080 unreachable." >&2; exit 1
