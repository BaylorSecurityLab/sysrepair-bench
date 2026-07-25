#!/bin/bash
# Verification for meta3-ubuntu/scenario-15: UnrealIRCd exposed on all
# interfaces -- compensating control (loopback the daemon, front TLS via
# stunnel). Exit 0 = remediated (PASS), Exit 1 = vulnerable or broken.
#
# DYNAMIC: bind addresses come from the LIVE listeners (/proc/net/tcp, state 0A,
# HEX ip:port; 1A0B=6667 1F83=8067 1A29=6697). Reachability of the raw IRC port
# from a non-loopback address is tested with a real TCP connect, and the TLS
# front is tested with a real openssl handshake that must reach an IRC banner.
# "Edited the conf but did not restart the daemon" leaves 6667 on 0.0.0.0 -> FAIL.
set -u
SELF_IP=$(hostname -i 2>/dev/null | awk '{print $1}')

bound_any() {   # $1 = hex port -> 0 if bound to all interfaces
    awk -v p=":$1" '$4=="0A" && $2=="00000000"p {f=1} END{exit !f}' /proc/net/tcp 2>/dev/null && return 0
    awk -v p=":$1" '$4=="0A" && $2=="00000000000000000000000000000000"p {f=1} END{exit !f}' /proc/net/tcp6 2>/dev/null && return 0
    return 1
}
present() {      # $1 = hex port -> 0 if anything LISTENs on it
    awk -v p=":$1" '$4=="0A" && $2 ~ p"$" {f=1} END{exit !f}' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

###############################################################################
# PoC 1: the raw IRC listeners (6667, 8067) must NOT be on all interfaces.
###############################################################################
if bound_any 1A0B; then
    echo "FAIL [PoC]: UnrealIRCd port 6667 is still bound to 0.0.0.0 / :: (raw IRC exposed to all interfaces)." >&2
    exit 1
fi
if bound_any 1F83; then
    echo "FAIL [PoC]: UnrealIRCd port 8067 is still bound to 0.0.0.0 / :: (raw IRC exposed to all interfaces)." >&2
    exit 1
fi
echo "PASS [PoC]: raw IRC listeners (6667/8067) are not bound to all interfaces."

###############################################################################
# PoC 2: raw IRC (6667) must be UNREACHABLE from a non-loopback address.
###############################################################################
if [ -n "$SELF_IP" ] && [ "$SELF_IP" != "127.0.0.1" ]; then
    if timeout 3 bash -c "exec 3<>/dev/tcp/$SELF_IP/6667" 2>/dev/null; then
        exec 3>&- 2>/dev/null || true
        echo "FAIL [PoC]: raw IRC port 6667 accepted a connection on non-loopback $SELF_IP -- still externally reachable." >&2
        exit 1
    fi
    echo "PASS [PoC]: raw IRC port 6667 refused connection on non-loopback $SELF_IP."
fi

###############################################################################
# stunnel TLS front: 6697 must be present on all interfaces and speak TLS to the
# IRC daemon.
###############################################################################
if ! present 1A29; then
    echo "FAIL [PoC-stunnel]: no listener on port 6697 -- TLS front not running." >&2
    exit 1
fi
if ! bound_any 1A29; then
    echo "FAIL [PoC-stunnel]: port 6697 is not bound to all interfaces -- trusted clients cannot reach the TLS front." >&2
    exit 1
fi
echo "PASS [PoC-stunnel]: port 6697 present on all interfaces."

BANNER=$( (printf 'NICK zt%s\r\nUSER zt zt zt :zt\r\n' "$$"; sleep 3) \
    | timeout 12 openssl s_client -connect 127.0.0.1:6697 -quiet 2>/dev/null | head -8 )
if echo "$BANNER" | grep -qiE 'irc|NOTICE|Welcome|Unreal|^:.* 00[0-9]'; then
    echo "PASS [Regression]: TLS handshake on 6697 reached an IRC banner (stunnel -> UnrealIRCd works)."
else
    echo "FAIL [Regression]: TLS connection on 6697 did not reach an IRC banner -- tunnel or daemon broken." >&2
    exit 1
fi

echo "All checks passed."
exit 0
