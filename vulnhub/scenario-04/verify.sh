#!/bin/bash
# Verification script for Scenario 07: Tomcat Weak Credentials
# VulnHub Source: Metasploitable 1
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable (FAIL)

USERS_XML="/var/lib/tomcat9/conf/tomcat-users.xml"

for WEAK in 'password="admin"' 'password="tomcat"' 'password="password"' 'password="manager"'; do
    if grep -q "$WEAK" "$USERS_XML" 2>/dev/null; then
        echo "FAIL [PoC]: Weak credential found in tomcat-users.xml: $WEAK"
        exit 1
    fi
done

echo "PASS [PoC]: No weak credentials in tomcat-users.xml."

CONTEXT="/usr/share/tomcat9-admin/manager/META-INF/context.xml"
if [ -f "$CONTEXT" ] && ! grep -q 'RemoteAddrValve' "$CONTEXT"; then
    echo "FAIL [PoC]: Manager app has no IP restriction (RemoteAddrValve missing)."
    exit 1
fi

echo "PASS [PoC]: Manager app has IP restriction."

if pgrep -f 'catalina\|tomcat' > /dev/null 2>&1; then
    echo "PASS [Regression]: Tomcat is running."
else
    echo "FAIL [Regression]: Tomcat is not running."
    exit 1
fi

echo "All checks passed."
exit 0
