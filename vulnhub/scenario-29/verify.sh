#!/bin/bash
# Scenario 29: the custom service must not listen on 0.0.0.0:8888. ss/netstat are
# absent, so we parse /proc/net/tcp{,6} for a LISTEN socket (state 0A) on port
# 8888 (hex 22B8) and require its bind address to be loopback, not 0.0.0.0. The
# service must be listening (a dead service is a FAIL). We also confirm the port
# is unreachable on the external interface but still reachable on loopback. The
# running ncat keeps its socket until relaunched, so "edited but not restarted"
# still shows 0.0.0.0 -> FAIL.
PASS=true
HEXPORT=$(printf '%04X' 8888)   # 22B8

LADDRS=$(awk -v p=":$HEXPORT" '$4=="0A" && $2 ~ p"$" {print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null)
if [ -z "$LADDRS" ]; then
    echo "FAIL [Regression]: nothing is listening on port 8888 (dead service)"; PASS=false
fi

bound_all=false
for a in $LADDRS; do
    ip=${a%%:*}
    case "$ip" in
        00000000|00000000000000000000000000000000) bound_all=true ;;
    esac
done
if $bound_all; then
    echo "FAIL [PoC]: service is listening on 0.0.0.0:8888 (all interfaces)"; PASS=false
elif [ -n "$LADDRS" ]; then
    echo "PASS [PoC]: service bound to a non-global address on 8888"
fi

IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=$(ip -o -4 addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
if [ -n "$IP" ] && [ "$IP" != "127.0.0.1" ]; then
    if timeout 4 bash -c "exec 3<>/dev/tcp/$IP/8888" 2>/dev/null; then
        echo "FAIL [PoC]: port 8888 reachable on external interface $IP"; PASS=false
    else
        echo "PASS [PoC]: port 8888 not reachable on external interface $IP"
    fi
fi

# Regression: the service must still serve on loopback.
if timeout 4 bash -c 'exec 3<>/dev/tcp/127.0.0.1/8888' 2>/dev/null; then
    echo "PASS [Regression]: service reachable on loopback"
else
    echo "FAIL [Regression]: service not reachable on loopback"; PASS=false
fi

if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
