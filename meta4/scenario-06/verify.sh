#!/bin/bash
# Scenario 06: Spring Cloud Function SpEL injection (CVE-2022-22963)
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

JAR=/opt/app/app.jar
[ -f "$JAR" ] || { echo "FAIL [PoC]: $JAR not found." >&2; exit 1; }

# Extract spring-cloud-function-web version from the fat jar
SCF_JAR=$(unzip -l "$JAR" 2>/dev/null | grep -oE 'BOOT-INF/lib/spring-cloud-function-web-[0-9.]+\.jar' | head -1)
[ -z "$SCF_JAR" ] && { echo "FAIL [PoC]: spring-cloud-function-web jar not found inside $JAR." >&2; exit 1; }

VER=$(echo "$SCF_JAR" | sed -E 's/.*spring-cloud-function-web-([0-9.]+)\.jar/\1/')

SAFE=0
case "$VER" in
    3.1.*) ver_ge "$VER" "3.1.7" && SAFE=1 ;;
    3.2.*) ver_ge "$VER" "3.2.3" && SAFE=1 ;;
    *)     ver_ge "$VER" "3.2.3" && SAFE=1 ;;
esac

if [ "$SAFE" != "1" ]; then
    echo "FAIL [PoC]: spring-cloud-function-web is $VER (need >= 3.2.3 or >= 3.1.7)." >&2
    exit 1
fi
echo "PASS [PoC]: spring-cloud-function-web upgraded to $VER."

# Regression: the uppercase function must still work
for i in $(seq 1 20); do
    R=$(curl -sf -m 3 -X POST -H 'Content-Type: text/plain' \
        -d 'hello' "http://127.0.0.1:8080/uppercase" 2>/dev/null || true)
    [ "$R" = "HELLO" ] && { echo "PASS [Regression]: /uppercase returns HELLO."; exit 0; }
    sleep 2
done
echo "FAIL [Regression]: /uppercase did not return HELLO." >&2
exit 1
