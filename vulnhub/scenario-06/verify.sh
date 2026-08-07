#!/bin/bash
# Verification: Scenario 06 - PHP No open_basedir (CWE-22 LFI)
# VulnHub Source: PwnOS 2.0
#
# PoC checks:        read.php cannot fetch files outside the web root
# Regression checks: read.php still serves files inside the web root
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
#
# Dynamic evidence: curl/nc are absent, so we issue a real HTTP request to the
# LIVE apache over bash /dev/tcp and inspect read.php's response body. This
# reflects the running mod_php SAPI, so a php.ini edit that never restarts apache
# FAILS. verify.sh must NOT start apache (the image CMD already did).
#
# Two-component protocol: nothing aborts early, so "enforced open_basedir but
# killed apache" reports security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

http_get() {  # $1 = path ; prints raw HTTP response
    timeout 10 bash -c '
        exec 3<>/dev/tcp/127.0.0.1/80 || exit 1
        printf "GET %s HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" "$1" >&3
        cat <&3
        exec 3>&-
    ' _ "$1" 2>/dev/null
}

# --- Regression: apache must be up and read.php must work inside the web root.
INSIDE=$(http_get "/read.php?f=/var/www/html/read.php")
if [ -z "$INSIDE" ]; then
    record_reg readphp_serves_webroot 0 "no HTTP response from apache - server down or read.php missing"
elif printf '%s' "$INSIDE" | grep -q 'file_get_contents'; then
    record_reg readphp_serves_webroot 1
else
    record_reg readphp_serves_webroot 0 "read.php could not read a file inside the web root (over-restricted?)"
fi

# --- PoC: LFI to a file OUTSIDE the web root must be blocked on the LIVE server.
# /etc/passwd is world-readable, so www-data CAN read it unless open_basedir
# stops PHP - making it the correct discriminator (unlike /etc/shadow which
# www-data can never read regardless of the fix).
OUT=$(http_get "/read.php?f=/etc/passwd")
if printf '%s' "$OUT" | grep -q 'root:.*:0:0:'; then
    record_poc lfi_outside_webroot_blocked 0 "read.php returned /etc/passwd over HTTP - open_basedir not enforced (php.ini may be set, but was apache restarted?)"
else
    record_poc lfi_outside_webroot_blocked 1
fi

verify_finish
