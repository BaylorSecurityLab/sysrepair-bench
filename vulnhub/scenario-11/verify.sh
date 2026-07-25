#!/bin/bash
# Verification: Scenario 11 - Nginx serves hidden/sensitive dotfiles (CWE-538)
# VulnHub Source: DC-5
#
# Exit 0 = remediated (hidden files are not served) AND normal content works
# Exit 1 = still vulnerable (/.env or /.git/config leak) OR nginx/php is down
#
# Dynamic evidence: curl/nc are absent, so we request the planted hidden files
# from the LIVE nginx over bash /dev/tcp. nginx reads its config only at
# start/reload, so a deny rule that is never reloaded still serves the files and
# this FAILS. The image CMD boots nginx (see .preserve-cmd); verify.sh must NOT
# start it - a dead server is a failure.

PASS=true

http_head1() {  # $1 = path ; prints first status line
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
    echo "FAIL [Regression]: no HTTP response - nginx is down."
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
if printf '%s' "$ROOT" | grep -q 'PHP Version'; then
    echo "PASS [Regression]: nginx + php-fpm serve index.php (phpinfo returned)."
else
    if printf '%s' "$ROOT" | grep -qE 'HTTP/1\.[01] 200'; then
        echo "PASS [Regression]: nginx serves index.php (HTTP 200)."
    else
        echo "FAIL [Regression]: index.php did not return 200/PHP (php-fpm 502 or nginx broken)."
        PASS=false
    fi
fi

# --- PoC: hidden files must NOT be served / leaked on the live server ---
check_hidden() {  # $1 path, $2 secret-marker
    local resp status
    resp=$(http_head1 "$1")
    status=$(printf '%s' "$resp" | head -1 | tr -d '\r')
    echo "  $1 -> ${status:-<none>}"
    if printf '%s' "$resp" | grep -qE 'HTTP/1\.[01] 200'; then
        echo "FAIL [PoC]: $1 is served (HTTP 200) - hidden file exposed."
        echo "            (config may have a deny rule, but was nginx reloaded?)"
        PASS=false
    fi
    if [ -n "$2" ] && printf '%s' "$resp" | grep -q "$2"; then
        echo "FAIL [PoC]: $1 leaked its secret contents ('$2')."
        PASS=false
    fi
}
check_hidden "/.env" "sr_super_secret_prod_pw"
check_hidden "/.git/config" "repositoryformatversion"
$PASS && echo "PASS [PoC]: hidden dotfiles (.env, .git) are not served by the live server."

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
