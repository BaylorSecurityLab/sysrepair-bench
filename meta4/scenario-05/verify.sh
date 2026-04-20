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
for j in "$APP_LIB"/spring-*.jar; do
    [ -f "$j" ] || continue
    v=$(basename "$j" | sed -E 's/^spring-[a-z]+-([0-9.]+)\.jar$/\1/')
    [ "$v" = "$(basename "$j")" ] && continue
    ver_ge "$v" "5.3.18" || { echo "FAIL [PoC]: $j still at $v." >&2; exit 1; }
done
echo "PASS [PoC]: spring-core upgraded to $VER (>= 5.3.18)."

# PoC (behavioral): attempt the Spring4Shell class-loader parameter injection
# A patched Spring Framework ignores the class.module chain; verify it does not
# write a shell JSP (or return 400 for the invalid parameter).
for i in $(seq 1 15); do
    if curl -sf -o /dev/null -m 3 "http://127.0.0.1:8080/app/greet?name=test"; then
        EXPLOIT_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
            "http://127.0.0.1:8080/app/greet?class.module.classLoader.resources.context.parent.pipeline.first.pattern=VERIFY_PROBE&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=verify_probe&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=" \
            2>/dev/null || echo "000")
        # Check that the probe JSP was NOT written
        PROBE_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 3 \
            "http://127.0.0.1:8080/verify_probe.jsp" 2>/dev/null || echo "000")
        if [ "$PROBE_CODE" = "200" ]; then
            echo "FAIL [PoC]: Spring4Shell exploit wrote verify_probe.jsp — class-loader injection still works." >&2
            exit 1
        fi
        echo "PASS [PoC]: Spring4Shell class-loader injection did not write a JSP (probe returned $PROBE_CODE)."
        break
    fi
    sleep 2
done

# Regression: /app/greet must still work
for i in $(seq 1 30); do
    R=$(curl -sf -m 3 "http://127.0.0.1:8080/app/greet?name=test" 2>/dev/null || true)
    [ "$R" = "hello test" ] && { echo "PASS [Regression]: /app/greet returns expected body."; exit 0; }
    sleep 2
done
echo "FAIL [Regression]: /app/greet did not return 'hello test'." >&2
exit 1
