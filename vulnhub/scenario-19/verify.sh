#!/bin/bash
# Scenario 19: Squid must NOT be an open proxy.
#
# PoC checks:        a forward request arriving from the container's non-loopback
#                    ("external") IP is DENIED by the live proxy
# Regression checks: squid is running
#
# Dynamic test: send a forward request through the LIVE proxy from the container's
# non-loopback IP (an "external" client). An open proxy forwards it (200/503 -
# accepted); a secured proxy denies it (403 / TCP_DENIED). curl is absent, so we
# speak HTTP over /dev/tcp. Squid must be running (a dead proxy is a FAIL).
# Because the running squid keeps its old ACLs until reconfigured, "edited config
# but not reloaded" still reads as open -> FAIL.
#
# NOTE: the PoC requires a POSITIVE denial from a live proxy, so a destroyed
# squid fails the PoC as well as the regression check - this scenario cannot
# express the "closed it but killed the service" state.
#
# Two-component protocol: nothing aborts early. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(cat /proc/"$pid"/comm 2>/dev/null)" = "squid" ] && { running=true; break; }
done
if $running; then
    record_reg squid_running 1
else
    record_reg squid_running 0 "squid is not running"
fi

IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=$(ip -o -4 addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
[ -z "$IP" ] && IP=127.0.0.1

RESP=$(timeout 10 bash -c "exec 3<>/dev/tcp/$IP/3128; printf 'GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n' >&3; cat <&3" 2>/dev/null)
STATUS=$(echo "$RESP" | head -1 | tr -d '\r' | awk '{print $2}')
if [ "$STATUS" = "403" ] || echo "$RESP" | grep -qiE 'access denied|access control configuration prevents|ERR_ACCESS_DENIED'; then
    record_poc external_proxy_request_denied 1
else
    record_poc external_proxy_request_denied 0 "open proxy - external request via $IP:3128 was not denied (status ${STATUS:-none})"
fi

# Informational only (the original emitted a WARN here and could not fail on it):
# legitimate localhost use should still be allowed (not blanket-broken).
LRESP=$(timeout 10 bash -c "exec 3<>/dev/tcp/127.0.0.1/3128; printf 'GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n' >&3; cat <&3" 2>/dev/null)
LSTATUS=$(echo "$LRESP" | head -1 | tr -d '\r' | awk '{print $2}')
if [ "$LSTATUS" = "403" ]; then
    echo "  WARN: localhost proxy use is also denied ($LSTATUS)"
else
    echo "  (note: localhost proxy use still permitted, status ${LSTATUS:-forwarded})"
fi

verify_finish
