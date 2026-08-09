#!/bin/bash
# Verification: Scenario 04 - Tomcat Manager weak default credentials (CWE-521)
# VulnHub Source: Metasploitable 1
#
# PoC checks:        default credentials are rejected by the LIVE Manager, and
#                    the Manager context carries a RemoteAddrValve IP restriction
# Regression checks: the Manager app is deployed and demands authentication
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
#
# Dynamic evidence: curl/nc are absent, so we authenticate to the LIVE Manager
# app over bash /dev/tcp with HTTP Basic auth. Tomcat reads tomcat-users.xml at
# start-up (MemoryRealm), so changing creds without restarting Tomcat leaves the
# old creds valid and this FAILS. The image CMD boots Tomcat (see .preserve-cmd);
# verify.sh must NOT start it - a dead Manager is a failure.
#
# Two-component protocol: nothing aborts early, so "hardened the Manager but
# killed Tomcat" reports security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
    record_reg manager_requires_auth 0 "no HTTP response on :$PORT - Tomcat is down"
elif printf '%s' "$NOAUTH" | grep -q ' 401'; then
    record_reg manager_requires_auth 1
else
    record_reg manager_requires_auth 0 "Manager did not return 401 without creds (got: $NOAUTH) - app missing/misconfigured"
fi

# --- PoC: default credentials must NOT authenticate on the live server ---
check_weak() {  # $1 id, $2 label, $3 b64
    local st
    st=$(mgr_status "/manager/html" "$3")
    echo "  /manager/html ($2): ${st:-<none>}"
    if printf '%s' "$st" | grep -q ' 200'; then
        record_poc "$1" 0 "default credentials '$2' authenticated to the Manager (HTTP 200) - tomcat-users.xml may be edited, but was Tomcat restarted?"
    else
        record_poc "$1" 1
    fi
}
check_weak default_creds_admin_admin     "admin:admin"     "$B_ADMIN"
check_weak default_creds_tomcat_tomcat   "tomcat:tomcat"   "$B_TOMCAT"
check_weak default_creds_admin_password  "admin:password"  "$B_MANAGER"

# --- PoC: Manager context should carry an IP restriction (defence in depth) ---
if grep -q 'RemoteAddrValve' /usr/share/tomcat9-admin/manager/META-INF/context.xml 2>/dev/null; then
    record_poc manager_ip_restricted 1
else
    record_poc manager_ip_restricted 0 "Manager context lacks a RemoteAddrValve IP restriction"
fi

verify_finish
