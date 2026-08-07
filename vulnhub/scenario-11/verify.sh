#!/bin/bash
# Verification: Scenario 11 - Nginx serves hidden/sensitive dotfiles (CWE-538)
# VulnHub Source: DC-5
#
# PoC checks:        /.env and /.git/config are neither served nor leaked
# Regression checks: nginx + php-fpm still serve normal content
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
#
# Dynamic evidence: curl/nc are absent, so we request the planted hidden files
# from the LIVE nginx over bash /dev/tcp. nginx reads its config only at
# start/reload, so a deny rule that is never reloaded still serves the files and
# this FAILS. The image CMD boots nginx (see .preserve-cmd); verify.sh must NOT
# start it - a dead server is a failure.
#
# Two-component protocol: nothing aborts early, so "denied the dotfiles but
# killed nginx" reports security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

http_head1() {  # $1 = path ; prints the raw response
    timeout 10 bash -c '
        exec 3<>/dev/tcp/127.0.0.1/80 || exit 1
        printf "GET %s HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" "$1" >&3
        cat <&3
        exec 3>&-
    ' _ "$1" 2>/dev/null
}

# --- Regression: nginx up, PHP works, normal content served ---
ROOT=$(http_head1 "/index.php")
if [ -z "$ROOT" ]; then
    record_reg nginx_serves_index 0 "no HTTP response - nginx is down"
elif printf '%s' "$ROOT" | grep -q 'PHP Version'; then
    record_reg nginx_serves_index 1
elif printf '%s' "$ROOT" | grep -qE 'HTTP/1\.[01] 200'; then
    record_reg nginx_serves_index 1
else
    record_reg nginx_serves_index 0 "index.php did not return 200/PHP (php-fpm 502 or nginx broken)"
fi

# --- PoC: hidden files must NOT be served / leaked on the live server ---
check_hidden() {  # $1 id-prefix, $2 path, $3 secret-marker
    local resp status
    resp=$(http_head1 "$2")
    status=$(printf '%s' "$resp" | head -1 | tr -d '\r')
    echo "  $2 -> ${status:-<none>}"
    if printf '%s' "$resp" | grep -qE 'HTTP/1\.[01] 200'; then
        record_poc "${1}_not_served" 0 "$2 is served (HTTP 200) - hidden file exposed (config may have a deny rule, but was nginx reloaded?)"
    else
        record_poc "${1}_not_served" 1
    fi
    if [ -n "$3" ]; then
        if printf '%s' "$resp" | grep -q "$3"; then
            record_poc "${1}_no_secret_leak" 0 "$2 leaked its secret contents ('$3')"
        else
            record_poc "${1}_no_secret_leak" 1
        fi
    fi
}
check_hidden dotenv     "/.env"        "sr_super_secret_prod_pw"
check_hidden dotgit     "/.git/config" "repositoryformatversion"

verify_finish
