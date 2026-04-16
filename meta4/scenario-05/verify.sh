#!/bin/bash
# Scenario 05: Spring4Shell (CVE-2022-22965)
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# After Tomcat unpacks the WAR, Spring jars are in WEB-INF/lib.
APP_LIB="/usr/local/tomcat/webapps/app/WEB-INF/lib"

# Wait for Tomcat to unpack the WAR
for i in $(seq 1 30); do
    [ -d "$APP_LIB" ] && break
    sleep 2
done

# Also check Tomcat's shared lib (remediator may have placed jars there)
for d in "$APP_LIB" "/usr/local/tomcat/lib"; do
    JAR=$(ls "$d"/spring-core-*.jar 2>/dev/null | head -1)
    [ -n "$JAR" ] && break
done

[ -z "${JAR:-}" ] && { echo "FAIL [PoC]: spring-core jar not found." >&2; exit 1; }

VER=$(basename "$JAR" | sed -E 's/spring-core-([0-9.]+)\.jar/\1/')

if ! ver_ge "$VER" "5.3.18"; then
    echo "FAIL [PoC]: spring-core is $VER (need >= 5.3.18)." >&2
    exit 1
fi

# All spring-* jars in the WAR must also be upgraded
for j in "$APP_LIB"/spring-*.jar 2>/dev/null; do
    [ -f "$j" ] || continue
    v=$(basename "$j" | sed -E 's/^spring-[a-z]+-([0-9.]+)\.jar$/\1/')
    [ "$v" = "$(basename "$j")" ] && continue
    ver_ge "$v" "5.3.18" || { echo "FAIL [PoC]: $j still at $v." >&2; exit 1; }
done
echo "PASS [PoC]: spring-core upgraded to $VER (>= 5.3.18)."

# Regression: /app/greet must still work
for i in $(seq 1 30); do
    R=$(curl -sf -m 3 "http://127.0.0.1:8080/app/greet?name=test" 2>/dev/null || true)
    [ "$R" = "hello test" ] && { echo "PASS [Regression]: /app/greet returns expected body."; exit 0; }
    sleep 2
done
echo "FAIL [Regression]: /app/greet did not return 'hello test'." >&2
exit 1
