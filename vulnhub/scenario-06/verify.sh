#!/bin/bash
# Verification: Scenario 06 - PHP No open_basedir (CWE-22 LFI)
# VulnHub Source: PwnOS 2.0
#
# Exit 0 = remediated (read.php cannot fetch files outside the web root, but
#          still serves files inside it)
# Exit 1 = still vulnerable (LFI reads /etc/passwd) OR apache is down
#
# Dynamic evidence: curl/nc are absent, so we issue a real HTTP request to the
# LIVE apache over bash /dev/tcp and inspect read.php's response body. This
# reflects the running mod_php SAPI, so a php.ini edit that never restarts apache
# FAILS. verify.sh must NOT start apache (the image CMD already did).

PASS=true

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
    echo "FAIL [Regression]: no HTTP response from apache - server down or read.php missing."
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
if printf '%s' "$INSIDE" | grep -q 'file_get_contents'; then
    echo "PASS [Regression]: read.php still serves files inside the web root."
else
    echo "FAIL [Regression]: read.php could not read a file inside the web root (over-restricted?)."
    PASS=false
fi

# --- PoC: LFI to a file OUTSIDE the web root must be blocked on the LIVE server.
# /etc/passwd is world-readable, so www-data CAN read it unless open_basedir
# stops PHP - making it the correct discriminator (unlike /etc/shadow which
# www-data can never read regardless of the fix).
OUT=$(http_get "/read.php?f=/etc/passwd")
if printf '%s' "$OUT" | grep -q 'root:.*:0:0:'; then
    echo "FAIL [PoC]: read.php returned /etc/passwd over HTTP - open_basedir not enforced."
    echo "            (php.ini may be set, but was apache restarted?)"
    PASS=false
else
    echo "PASS [PoC]: read.php cannot read /etc/passwd (open_basedir enforced on the live server)."
fi

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
