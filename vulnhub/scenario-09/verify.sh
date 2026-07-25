#!/bin/bash
# Verification: Scenario 09 - PHP Command Injection (CWE-78)
# VulnHub Source: DC-4
#
# Exit 0 = remediated (POSTing a command no longer executes it) AND apache serves
# Exit 1 = still vulnerable (command runs) OR apache is down
#
# Dynamic evidence: curl/nc are absent, so we POST the exploit to the LIVE
# cmd.php over bash /dev/tcp and require that the injected command does NOT run.
# mod_php re-reads the script per request, so the fix (remove/sanitise cmd.php)
# takes effect without a restart - there is no not-restarted variant. verify.sh
# must NOT start apache; a dead server is a failure.

PASS=true

http_post() {  # $1 = path, $2 = body ; prints raw HTTP response
    timeout 10 bash -c '
        exec 3<>/dev/tcp/127.0.0.1/80 || exit 1
        printf "POST %s HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s" "$1" "${#2}" "$2" >&3
        cat <&3
        exec 3>&-
    ' _ "$1" "$2" 2>/dev/null
}
http_get() {  # $1 = path
    timeout 10 bash -c '
        exec 3<>/dev/tcp/127.0.0.1/80 || exit 1
        printf "GET %s HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" "$1" >&3
        cat <&3
        exec 3>&-
    ' _ "$1" 2>/dev/null
}

# --- Regression: apache must be alive ---
ROOT=$(http_get "/")
if [ -z "$ROOT" ]; then
    echo "FAIL [Regression]: no HTTP response - apache is down."
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
if printf '%s' "$ROOT" | grep -qE 'HTTP/1\.[01] (200|403|404)'; then
    echo "PASS [Regression]: apache is serving HTTP."
else
    echo "FAIL [Regression]: apache did not return a valid HTTP status."
    PASS=false
fi

# --- PoC: injected command must NOT execute on the live server ---
RESP=$(http_post "/cmd.php" "cmd=id")
if printf '%s' "$RESP" | grep -qE 'uid=[0-9]+.*gid=[0-9]+'; then
    echo "FAIL [PoC]: 'id' executed via cmd.php - command injection still works."
    PASS=false
else
    echo "PASS [PoC]: injected 'id' did not execute (no uid=... in response)."
fi

# Second payload to defeat a naive keyword filter (command substitution).
RESP2=$(http_post "/cmd.php" "cmd=echo%20SR_\$(id%20-u)_END")
if printf '%s' "$RESP2" | grep -qE 'SR_[0-9]+_END'; then
    echo "FAIL [PoC]: command substitution executed via cmd.php."
    PASS=false
else
    echo "PASS [PoC]: command substitution payload did not execute."
fi

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
