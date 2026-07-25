#!/bin/bash
# Verification: Scenario 02 - SQL Injection in PHP web app (CWE-89)
# VulnHub Source: Kioptrix Level 1.1
#
# Exit 0 = remediated (injection returns no extra rows) AND legit search works
# Exit 1 = still vulnerable (injection leaks rows) OR the stack is down
#
# Dynamic evidence: curl/nc are absent, so we drive the LIVE search.php over
# bash /dev/tcp and mount a real SQL injection. The table holds exactly two
# rows (admin, user1). A tautology injection on a value that matches NOTHING
# ("zzz' OR '1'='1") returns BOTH rows while vulnerable, and ZERO rows once the
# query is parameterized. mod_php re-reads the script per request, so this
# reflects the current code with no restart needed. verify.sh must NOT start the
# services (the image CMD already did); a dead stack is a failure.

PASS=true

http_get() {  # $1 = path ; prints response body (after headers)
    timeout 10 bash -c '
        exec 3<>/dev/tcp/127.0.0.1/80 || exit 1
        printf "GET %s HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" "$1" >&3
        cat <&3
        exec 3>&-
    ' _ "$1" 2>/dev/null
}

# --- Regression: legitimate search for an existing user must return that row ---
LEGIT=$(http_get "/search.php?q=admin")
if [ -z "$LEGIT" ]; then
    echo "FAIL [Regression]: no HTTP response - apache/mariadb down or search.php missing."
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
if printf '%s' "$LEGIT" | grep -q 'admin'; then
    echo "PASS [Regression]: legitimate search q=admin still returns the admin row."
else
    echo "FAIL [Regression]: legitimate search returned no data - app or DB link broken."
    PASS=false
fi

# --- PoC: tautology injection on a non-matching value must leak NOTHING ---
# URL-encoded: zzz' OR '1'='1
INJ=$(http_get "/search.php?q=zzz%27%20OR%20%271%27%3D%271")
if printf '%s' "$INJ" | grep -qE 'admin|user1'; then
    echo "FAIL [PoC]: SQL injection leaked rows - tautology returned user data:"
    printf '%s\n' "$INJ" | grep -oE 'admin|user1' | sort -u | sed 's/^/            /'
    PASS=false
else
    echo "PASS [PoC]: tautology injection returned no rows (query is parameterized)."
fi

# --- PoC #2: UNION-style injection must not surface data either ---
# zzz' UNION SELECT name FROM users -- -
INJ2=$(http_get "/search.php?q=zzz%27%20UNION%20SELECT%20name%20FROM%20users%20--%20-")
if printf '%s' "$INJ2" | grep -qE 'admin|user1'; then
    echo "FAIL [PoC]: UNION injection leaked rows from the users table."
    PASS=false
else
    echo "PASS [PoC]: UNION injection returned no rows."
fi

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
