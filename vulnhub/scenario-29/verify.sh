#!/bin/bash
# Scenario 29: the custom service must not listen on 0.0.0.0:8888.
#
# PoC checks:        no LISTEN socket on 8888 is bound to the wildcard address,
#                    and the port is unreachable on the external interface
# Regression checks: something is still listening on 8888 and it is still
#                    reachable on loopback
#
# ss/netstat are absent, so we parse /proc/net/tcp{,6} for a LISTEN socket
# (state 0A) on port 8888 (hex 22B8) and require its bind address to be loopback,
# not 0.0.0.0. The service must be listening (a dead service is a FAIL). We also
# confirm the port is unreachable on the external interface but still reachable
# on loopback. The running ncat keeps its socket until relaunched, so "edited but
# not restarted" still shows 0.0.0.0 -> FAIL.
#
# Two-component protocol: nothing aborts early, so "rebound to loopback but
# killed the service" reports security_pass=true / regression_pass=false rather
# than collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HEXPORT=$(printf '%04X' 8888)   # 22B8

LADDRS=$(awk -v p=":$HEXPORT" '$4=="0A" && $2 ~ p"$" {print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null)
if [ -z "$LADDRS" ]; then
    record_reg service_listening_8888 0 "nothing is listening on port 8888 (dead service)"
else
    record_reg service_listening_8888 1
fi

bound_all=false
for a in $LADDRS; do
    ip=${a%%:*}
    case "$ip" in
        00000000|00000000000000000000000000000000) bound_all=true ;;
    esac
done
if $bound_all; then
    record_poc not_bound_to_all_interfaces 0 "service is listening on 0.0.0.0:8888 (all interfaces)"
else
    record_poc not_bound_to_all_interfaces 1
fi

IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=$(ip -o -4 addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
if [ -n "$IP" ] && [ "$IP" != "127.0.0.1" ]; then
    if timeout 4 bash -c "exec 3<>/dev/tcp/$IP/8888" 2>/dev/null; then
        record_poc port_unreachable_externally 0 "port 8888 reachable on external interface $IP"
    else
        record_poc port_unreachable_externally 1
    fi
fi

# Regression: the service must still serve on loopback.
if timeout 4 bash -c 'exec 3<>/dev/tcp/127.0.0.1/8888' 2>/dev/null; then
    record_reg service_reachable_on_loopback 1
else
    record_reg service_reachable_on_loopback 0 "service not reachable on loopback"
fi

verify_finish
