#!/bin/bash
set -u
WEB_XML=/usr/local/tomcat/conf/web.xml
ROOT_XML=/usr/local/tomcat/conf/Catalina/localhost/ROOT.xml

# Extract tomcat version
TOMCAT_VER=$(grep -oE 'Apache Tomcat/[0-9.]+' /usr/local/tomcat/RELEASE-NOTES 2>/dev/null | head -1 | sed 's|Apache Tomcat/||')
[ -z "$TOMCAT_VER" ] && TOMCAT_VER=$(ls /usr/local/tomcat/lib/catalina.jar >/dev/null 2>&1 && /usr/local/tomcat/bin/version.sh 2>/dev/null | grep 'Server number' | awk -F: '{print $2}' | tr -d ' ')

ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# Check 1: default servlet readonly=true OR Tomcat upgraded
READONLY_SAFE=0
# Grab the first <param-value> that follows readonly</param-name>
READONLY=$(awk '/<param-name>readonly<\/param-name>/{flag=1;next} flag && /<param-value>/{print;exit}' "$WEB_XML" | grep -oE 'true|false' | head -1)
if [ "$READONLY" = "true" ] || [ -z "$READONLY" ]; then
    READONLY_SAFE=1
fi

# Check 2: PersistentManager/FileStore removed
PERSIST_SAFE=1
if [ -f "$ROOT_XML" ] && grep -qE 'PersistentManager|FileStore' "$ROOT_XML"; then
    PERSIST_SAFE=0
fi

# Check 3: version upgraded
VER_SAFE=0
case "$TOMCAT_VER" in
    9.0.*)  ver_ge "$TOMCAT_VER" "9.0.99"  && VER_SAFE=1 ;;
    10.1.*) ver_ge "$TOMCAT_VER" "10.1.35" && VER_SAFE=1 ;;
    11.0.*) ver_ge "$TOMCAT_VER" "11.0.3"  && VER_SAFE=1 ;;
esac

if [ "$READONLY_SAFE" = "1" ] || [ "$PERSIST_SAFE" = "1" ] || [ "$VER_SAFE" = "1" ]; then
    echo "PASS [PoC]: readonly_safe=$READONLY_SAFE persist_removed=$PERSIST_SAFE version_safe=$VER_SAFE (tomcat=$TOMCAT_VER)."
else
    echo "FAIL [PoC]: readonly=false, PersistentManager/FileStore still configured, and Tomcat $TOMCAT_VER is vulnerable." >&2
    exit 1
fi

# PoC (behavioral): attempt partial PUT upload — must be rejected (403/405)
for i in $(seq 1 10); do
    if curl -sf -o /dev/null -m 3 "http://127.0.0.1:8080/"; then
        PUT_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
            -X PUT -H 'Content-Range: bytes 0-3/4' \
            -d 'TEST' "http://127.0.0.1:8080/verify_probe.txt" 2>/dev/null || echo "000")
        if [ "$PUT_CODE" = "201" ] || [ "$PUT_CODE" = "204" ]; then
            echo "FAIL [PoC]: Partial PUT succeeded (HTTP $PUT_CODE) — readonly=false still active." >&2
            exit 1
        fi
        echo "PASS [PoC]: Partial PUT rejected (HTTP $PUT_CODE) — readonly or patched."
        break
    fi
    sleep 2
done

# Regression: Tomcat must still respond on 8080
for i in $(seq 1 20); do
    curl -sf -o /dev/null -m 3 "http://127.0.0.1:8080/" && { echo "PASS [Regression]: Tomcat HTTP 8080 reachable."; exit 0; }
    sleep 2
done
echo "FAIL [Regression]: Tomcat HTTP 8080 not reachable." >&2; exit 1
