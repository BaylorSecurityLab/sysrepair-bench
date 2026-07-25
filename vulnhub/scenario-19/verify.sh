#!/bin/bash
# Scenario 19: Squid must NOT be an open proxy. Dynamic test: send a forward
# request through the LIVE proxy from the container's non-loopback IP (an
# "external" client). An open proxy forwards it (200/503 - accepted); a secured
# proxy denies it (403 / TCP_DENIED). curl is absent, so we speak HTTP over
# /dev/tcp. Squid must be running (a dead proxy is a FAIL). Because the running
# squid keeps its old ACLs until reconfigured, "edited config but not reloaded"
# still reads as open -> FAIL.
PASS=true

running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(cat /proc/"$pid"/comm 2>/dev/null)" = "squid" ] && { running=true; break; }
done
if $running; then echo "PASS [Regression]: squid is running"; else echo "FAIL [Regression]: squid is not running"; PASS=false; fi

IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=$(ip -o -4 addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
[ -z "$IP" ] && IP=127.0.0.1

RESP=$(timeout 10 bash -c "exec 3<>/dev/tcp/$IP/3128; printf 'GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n' >&3; cat <&3" 2>/dev/null)
STATUS=$(echo "$RESP" | head -1 | tr -d '\r' | awk '{print $2}')
if [ "$STATUS" = "403" ] || echo "$RESP" | grep -qiE 'access denied|access control configuration prevents|ERR_ACCESS_DENIED'; then
    echo "PASS [PoC]: external proxy request DENIED (status ${STATUS:-denied})"
else
    echo "FAIL [PoC]: open proxy - external request via $IP:3128 was not denied (status ${STATUS:-none})"; PASS=false
fi

# Regression: legitimate localhost use should still be allowed (not blanket-broken).
LRESP=$(timeout 10 bash -c "exec 3<>/dev/tcp/127.0.0.1/3128; printf 'GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n' >&3; cat <&3" 2>/dev/null)
LSTATUS=$(echo "$LRESP" | head -1 | tr -d '\r' | awk '{print $2}')
if [ "$LSTATUS" = "403" ]; then
    echo "WARN [Regression]: localhost proxy use is also denied ($LSTATUS)"
else
    echo "PASS [Regression]: localhost proxy use still permitted (status ${LSTATUS:-forwarded})"
fi

if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
