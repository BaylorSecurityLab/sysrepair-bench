#!/bin/bash
# Verification: Scenario 04 - Tomcat Manager weak default credentials (CWE-521)
# VulnHub Source: Metasploitable 1
#
# Exit 0 = remediated (default creds rejected by the LIVE Manager) AND Tomcat up
# Exit 1 = still vulnerable (admin:admin / tomcat:tomcat authenticate) OR down
#
# Dynamic evidence: curl/nc are absent, so we authenticate to the LIVE Manager
# app over bash /dev/tcp with HTTP Basic auth. Tomcat reads tomcat-users.xml at
# start-up (MemoryRealm), so changing creds without restarting Tomcat leaves the
# old creds valid and this FAILS. The image CMD boots Tomcat (see .preserve-cmd);
# verify.sh must NOT start it - a dead Manager is a failure.

PASS=true
PORT=8080

# $1 = path, $2 = base64(user:pass) or empty ; prints the HTTP status line
mgr_status() {
    local auth_hdr=""
    [ -n "$2" ] && auth_hdr="Authorization: Basic $2\r\n"
    timeout 12 bash -c '
        exec 3<>/dev/tcp/127.0.0.1/'"$PORT"' || exit 1
        printf "GET %s HTTP/1.0\r\nHost: localhost\r\n'"$auth_hdr"'Connection: close\r\n\r\n" "$1" >&3
        head -1 <&3
        exec 3>&-
    ' _ "$1" 2>/dev/null | tr -d '\r'
}

# base64 of default credential pairs.
B_ADMIN=$(printf '%s' 'admin:admin'   | base64 2>/dev/null)
B_TOMCAT=$(printf '%s' 'tomcat:tomcat' | base64 2>/dev/null)
B_MANAGER=$(printf '%s' 'admin:password' | base64 2>/dev/null)

# --- Regression: Manager app must be deployed and demanding auth ---
NOAUTH=$(mgr_status "/manager/html" "")
echo "  /manager/html (no auth): ${NOAUTH:-<none>}"
if [ -z "$NOAUTH" ]; then
    echo "FAIL [Regression]: no HTTP response on :$PORT - Tomcat is down."
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
if printf '%s' "$NOAUTH" | grep -q ' 401'; then
    echo "PASS [Regression]: Manager app is deployed and requires authentication (401)."
else
    echo "FAIL [Regression]: Manager did not return 401 without creds (got: $NOAUTH) - app missing/misconfigured."
    PASS=false
fi

# --- PoC: default credentials must NOT authenticate on the live server ---
check_weak() {  # $1 label, $2 b64
    local st
    st=$(mgr_status "/manager/html" "$2")
    echo "  /manager/html ($1): ${st:-<none>}"
    if printf '%s' "$st" | grep -q ' 200'; then
        echo "FAIL [PoC]: default credentials '$1' authenticated to the Manager (HTTP 200)."
        echo "            (tomcat-users.xml may be edited, but was Tomcat restarted?)"
        PASS=false
    else
        echo "PASS [PoC]: default credentials '$1' rejected."
    fi
}
check_weak "admin:admin"     "$B_ADMIN"
check_weak "tomcat:tomcat"   "$B_TOMCAT"
check_weak "admin:password"  "$B_MANAGER"

# --- Secondary: Manager context should carry an IP restriction (defence) ---
if grep -q 'RemoteAddrValve' /usr/share/tomcat9-admin/manager/META-INF/context.xml 2>/dev/null; then
    echo "PASS [Hardening]: Manager context has a RemoteAddrValve IP restriction."
else
    echo "FAIL [Hardening]: Manager context lacks a RemoteAddrValve IP restriction."
    PASS=false
fi

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
