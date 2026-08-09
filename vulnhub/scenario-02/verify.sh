#!/bin/bash
# Verification: Scenario 02 - SQL Injection in PHP web app (CWE-89)
# VulnHub Source: Kioptrix Level 1.1
#
# PoC checks:        tautology and UNION injections leak no rows
# Regression checks: a legitimate search still returns its row
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
#
# Dynamic evidence: curl/nc are absent, so we drive the LIVE search.php over
# bash /dev/tcp and mount a real SQL injection. The table holds exactly two
# rows (admin, user1). A tautology injection on a value that matches NOTHING
# ("zzz' OR '1'='1") returns BOTH rows while vulnerable, and ZERO rows once the
# query is parameterized. mod_php re-reads the script per request, so this
# reflects the current code with no restart needed. verify.sh must NOT start the
# services (the image CMD already did); a dead stack is a failure.
#
# Two-component protocol: nothing aborts early, so "closed the injection but
# killed apache/mariadb" reports security_pass=true / regression_pass=false.
# See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
    record_reg legit_search_returns_row 0 "no HTTP response - apache/mariadb down or search.php missing"
elif printf '%s' "$LEGIT" | grep -q 'admin'; then
    record_reg legit_search_returns_row 1
else
    record_reg legit_search_returns_row 0 "legitimate search returned no data - app or DB link broken"
fi

# --- PoC: tautology injection on a non-matching value must leak NOTHING ---
# URL-encoded: zzz' OR '1'='1
INJ=$(http_get "/search.php?q=zzz%27%20OR%20%271%27%3D%271")
if printf '%s' "$INJ" | grep -qE 'admin|user1'; then
    LEAKED=$(printf '%s\n' "$INJ" | grep -oE 'admin|user1' | sort -u | tr '\n' ' ')
    record_poc tautology_injection_blocked 0 "SQL injection leaked rows - tautology returned user data: $LEAKED"
else
    record_poc tautology_injection_blocked 1
fi

# --- PoC #2: UNION-style injection must not surface data either ---
# zzz' UNION SELECT name FROM users -- -
INJ2=$(http_get "/search.php?q=zzz%27%20UNION%20SELECT%20name%20FROM%20users%20--%20-")
if printf '%s' "$INJ2" | grep -qE 'admin|user1'; then
    record_poc union_injection_blocked 0 "UNION injection leaked rows from the users table"
else
    record_poc union_injection_blocked 1
fi

verify_finish
