#!/bin/bash
# Scenario 22: PHP must NOT execute in the uploads directory.
#
# PoC checks:        a probe .php dropped into the uploads dir is NOT executed
#                    when fetched from the live apache
# Regression checks: apache is running
#
# Dynamic check: drop a probe .php into /var/www/html/uploads and fetch it from
# the LIVE apache over HTTP (curl is absent -> /dev/tcp). If it executes we see
# the computed marker, which means webshell RCE is possible -> FAIL. Apache must
# be running, and the disabling directive is server config that only takes effect
# after a restart, so "edited but not restarted" still executes -> FAIL.
#
# Two-component protocol: nothing aborts early, so "disabled PHP in uploads but
# killed apache" reports security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

UP=/var/www/html/uploads
PROBE="$UP/__s22_probe_$$.php"
cleanup(){ rm -f "$PROBE" 2>/dev/null; }
trap cleanup EXIT INT TERM

running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(cat /proc/"$pid"/comm 2>/dev/null)" = "apache2" ] && { running=true; break; }
done
if $running; then
    record_reg apache_running 1
else
    record_reg apache_running 0 "apache is not running"
fi

echo '<?php echo "S22EXEC:".(6*7); ?>' > "$PROBE" 2>/dev/null
BN=$(basename "$PROBE")
RESP=$(timeout 8 bash -c "exec 3<>/dev/tcp/127.0.0.1/80; printf 'GET /uploads/$BN HTTP/1.0\r\nHost: x\r\n\r\n' >&3; cat <&3" 2>/dev/null)
if echo "$RESP" | grep -q 'S22EXEC:42'; then
    record_poc php_not_executed_in_uploads 0 "PHP executed in uploads dir (webshell RCE possible)"
else
    record_poc php_not_executed_in_uploads 1
fi

cleanup; trap - EXIT INT TERM
verify_finish
