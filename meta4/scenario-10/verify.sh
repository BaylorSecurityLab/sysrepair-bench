#!/bin/bash
set -u
WEB_XML=/usr/local/tomcat/conf/web.xml
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

VER=$(/usr/local/tomcat/bin/version.sh 2>/dev/null | awk -F: '/Server number/{gsub(/[[:space:]]/,"",$2);print $2}')
[ -z "$VER" ] && VER=$(grep -oE 'Apache Tomcat/[0-9.]+' /usr/local/tomcat/RELEASE-NOTES 2>/dev/null | head -1 | sed 's|.*/||')

READONLY=$(awk '/<servlet-class>org\.apache\.catalina\.servlets\.DefaultServlet/,/<\/servlet>/' "$WEB_XML" \
           | awk '/<param-name>readonly</{flag=1;next} flag && /<param-value>/{print;exit}' \
           | grep -oE 'true|false' | head -1)

VER_SAFE=0
case "$VER" in
    9.0.*)  ver_ge "$VER" "9.0.98"  && VER_SAFE=1 ;;
    10.1.*) ver_ge "$VER" "10.1.34" && VER_SAFE=1 ;;
    11.0.*) ver_ge "$VER" "11.0.2"  && VER_SAFE=1 ;;
esac

if [ "$READONLY" = "true" ] || [ -z "$READONLY" ] || [ "$VER_SAFE" = "1" ]; then
    echo "PASS [PoC]: readonly='$READONLY' tomcat=$VER ver_safe=$VER_SAFE."
else
    echo "FAIL [PoC]: readonly=false AND tomcat $VER vulnerable." >&2; exit 1
fi

# PoC (behavioral): attempt PUT upload — must be rejected (403/405)
for i in $(seq 1 10); do
    if curl -sf -o /dev/null -m 3 "http://127.0.0.1:8080/"; then
        PUT_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
            -X PUT -d 'TEST' "http://127.0.0.1:8080/verify_probe.txt" 2>/dev/null || echo "000")
        if [ "$PUT_CODE" = "201" ] || [ "$PUT_CODE" = "204" ]; then
            echo "FAIL [PoC]: PUT upload succeeded (HTTP $PUT_CODE) — readonly=false still active." >&2
            exit 1
        fi
        echo "PASS [PoC]: PUT rejected (HTTP $PUT_CODE)."
        break
    fi
    sleep 2
done

for i in $(seq 1 20); do
    curl -sf -o /dev/null -m 3 http://127.0.0.1:8080/ && { echo "PASS [Regression]: Tomcat 8080 reachable."; exit 0; }
    sleep 2
done
echo "FAIL [Regression]: Tomcat 8080 unreachable." >&2; exit 1
