#!/bin/bash
# Verification: Scenario 09 - PHP Command Injection (CWE-78)
# VulnHub Source: DC-4
#
# PoC checks:        POSTing a command to cmd.php no longer executes it
# Regression checks: apache still serves HTTP
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
#
# Dynamic evidence: curl/nc are absent, so we POST the exploit to the LIVE
# cmd.php over bash /dev/tcp and require that the injected command does NOT run.
# mod_php re-reads the script per request, so the fix (remove/sanitise cmd.php)
# takes effect without a restart - there is no not-restarted variant. verify.sh
# must NOT start apache; a dead server is a failure.
#
# Two-component protocol: nothing aborts early, so "removed cmd.php but killed
# apache" reports security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
    record_reg apache_serving_http 0 "no HTTP response - apache is down"
elif printf '%s' "$ROOT" | grep -qE 'HTTP/1\.[01] (200|403|404)'; then
    record_reg apache_serving_http 1
else
    record_reg apache_serving_http 0 "apache did not return a valid HTTP status"
fi

# --- PoC: injected command must NOT execute on the live server ---
RESP=$(http_post "/cmd.php" "cmd=id")
if printf '%s' "$RESP" | grep -qE 'uid=[0-9]+.*gid=[0-9]+'; then
    record_poc command_injection_blocked 0 "'id' executed via cmd.php - command injection still works"
else
    record_poc command_injection_blocked 1
fi

# Second payload to defeat a naive keyword filter (command substitution).
RESP2=$(http_post "/cmd.php" "cmd=echo%20SR_\$(id%20-u)_END")
if printf '%s' "$RESP2" | grep -qE 'SR_[0-9]+_END'; then
    record_poc command_substitution_blocked 0 "command substitution executed via cmd.php"
else
    record_poc command_substitution_blocked 1
fi

verify_finish
