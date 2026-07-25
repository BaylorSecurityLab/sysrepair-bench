#!/bin/bash
# Scenario 22: PHP must NOT execute in the uploads directory. Dynamic check: drop
# a probe .php into /var/www/html/uploads and fetch it from the LIVE apache over
# HTTP (curl is absent -> /dev/tcp). If it executes we see the computed marker,
# which means webshell RCE is possible -> FAIL. Apache must be running, and the
# disabling directive is server config that only takes effect after a restart, so
# "edited but not restarted" still executes -> FAIL.
PASS=true
UP=/var/www/html/uploads
PROBE="$UP/__s22_probe_$$.php"
cleanup(){ rm -f "$PROBE" 2>/dev/null; }
trap cleanup EXIT INT TERM

running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(cat /proc/"$pid"/comm 2>/dev/null)" = "apache2" ] && { running=true; break; }
done
if $running; then echo "PASS [Regression]: apache is running"; else echo "FAIL [Regression]: apache is not running"; PASS=false; fi

echo '<?php echo "S22EXEC:".(6*7); ?>' > "$PROBE" 2>/dev/null
BN=$(basename "$PROBE")
RESP=$(timeout 8 bash -c "exec 3<>/dev/tcp/127.0.0.1/80; printf 'GET /uploads/$BN HTTP/1.0\r\nHost: x\r\n\r\n' >&3; cat <&3" 2>/dev/null)
if echo "$RESP" | grep -q 'S22EXEC:42'; then
    echo "FAIL [PoC]: PHP executed in uploads dir (webshell RCE possible)"; PASS=false
else
    echo "PASS [PoC]: PHP not executed in uploads dir"
fi

cleanup; trap - EXIT INT TERM
if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
