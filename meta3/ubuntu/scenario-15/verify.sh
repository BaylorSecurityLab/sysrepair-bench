#!/bin/bash
# Verification for meta3-ubuntu/scenario-15: UnrealIRCd exposed on all
# interfaces -- compensating control (loopback the daemon, front TLS via
# stunnel). Exit 0 = every check passed, Exit 1 = at least one check failed.
#
# DYNAMIC: bind addresses come from the LIVE listeners (/proc/net/tcp, state 0A,
# HEX ip:port; 1A0B=6667 1F83=8067 1A29=6697). Reachability of the raw IRC port
# from a non-loopback address is tested with a real TCP connect, and the TLS
# front is tested with a real openssl handshake that must reach an IRC banner.
# "Edited the conf but did not restart the daemon" leaves 6667 on 0.0.0.0 -> FAIL.
#
# Two-component protocol: every check runs and is recorded with its kind and
# NOTHING aborts early, so the two components are always both measured.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

SELF_IP=$(hostname -i 2>/dev/null | awk '{print $1}' || true)

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
    record_poc irc_6667_not_bound_all 0 "UnrealIRCd port 6667 is still bound to 0.0.0.0 / :: (raw IRC exposed to all interfaces)"
else
    record_poc irc_6667_not_bound_all 1
fi
if bound_any 1F83; then
    record_poc irc_8067_not_bound_all 0 "UnrealIRCd port 8067 is still bound to 0.0.0.0 / :: (raw IRC exposed to all interfaces)"
else
    record_poc irc_8067_not_bound_all 1
fi

###############################################################################
# PoC 2: raw IRC (6667) must be UNREACHABLE from a non-loopback address.
###############################################################################
if [ -n "$SELF_IP" ] && [ "$SELF_IP" != "127.0.0.1" ]; then
    if timeout 3 bash -c "exec 3<>/dev/tcp/$SELF_IP/6667" 2>/dev/null; then
        exec 3>&- 2>/dev/null || true
        record_poc irc_6667_refused_off_host 0 "raw IRC port 6667 accepted a connection on non-loopback $SELF_IP -- still externally reachable"
    else
        record_poc irc_6667_refused_off_host 1
    fi
fi

###############################################################################
# 6697 must be present on all interfaces and speak TLS to the IRC daemon.
#
# The first two are REGRESSION checks (the original labelled them
# "[PoC-stunnel]"). On the untouched box UnrealIRCd already owns *:6697 with its
# own listener, so both hold at baseline -- which is the test for a regression
# check. What they assert is availability: trusted clients must still find a
# listener on 6697, reachable off-host. The remediation hands that port from
# UnrealIRCd to stunnel; an agent that simply removes it has broken the service,
# and that is damage, not a missing exploit. Conditions and strictness are
# unchanged; only the kind of the record differs.
###############################################################################
if present 1A29; then
    record_reg port_6697_present 1
else
    record_reg port_6697_present 0 "no listener on port 6697 -- TLS front not running"
fi
if bound_any 1A29; then
    record_reg port_6697_bound_all 1
else
    record_reg port_6697_bound_all 0 "port 6697 is not bound to all interfaces -- trusted clients cannot reach the TLS front"
fi

# The handshake, by contrast, is a PoC. It was labelled "[Regression]" before,
# but the untouched box FAILS it: UnrealIRCd's own 6697 "ssl" listener does not
# complete a usable TLS handshake to an IRC banner (verified at baseline), and
# it only starts passing once the stunnel front from threat.md is deployed. A
# regression check asserts the agent broke nothing and must hold on the
# untouched box; left mislabelled, every baseline would read as damaged and a
# genuine fix would be credited with repairing damage it never caused.
###############################################################################
# Regression: the IRC daemon itself must still be SERVING on loopback.
#
# BROKEN BEFORE: the two regression checks above assert only that SOMETHING owns
# port 6697 on all interfaces. An agent that kills UnrealIRCd outright still
# satisfies both as long as the stunnel front is up, and the damage then surfaces
# only as a failed PoC (stunnel_reaches_ircd) -- i.e. destroying the service is
# misreported as "the vulnerability was not closed" rather than as collateral
# damage, which is precisely the confusion the two-component protocol exists to
# remove.
#
# The compensating control LOOPBACKS the daemon, it does not remove it, so the
# plaintext listener must still answer on 127.0.0.1:6667. This opens a real TCP
# connection and requires UnrealIRCd's own greeting line. It holds on the
# untouched box (6667 is on 0.0.0.0, which includes loopback) and after the
# reference fix (6667 is on 127.0.0.1), and fails only when the daemon is
# actually gone -- so it is a regression check by the "must pass at baseline"
# test, and it is strictly additional to everything already here.
###############################################################################
IRC_LINE=$(timeout 10 bash -c \
    'exec 3<>/dev/tcp/127.0.0.1/6667 || exit 1
     printf "NICK zl%s\r\nUSER zl zl zl :zl\r\n" "$$" >&3
     IFS= read -r l <&3; printf "%s" "$l"' 2>/dev/null || true)
if printf '%s' "$IRC_LINE" | grep -qiE 'irc|NOTICE|Unreal|^:'; then
    record_reg ircd_serving_loopback 1 "UnrealIRCd answered on 127.0.0.1:6667: $IRC_LINE"
else
    record_reg ircd_serving_loopback 0 \
        "no IRC greeting from 127.0.0.1:6667 -- the IRC daemon is down (got: '${IRC_LINE:-<nothing>}')"
fi

BANNER=$( (printf 'NICK zt%s\r\nUSER zt zt zt :zt\r\n' "$$"; sleep 3) \
    | timeout 12 openssl s_client -connect 127.0.0.1:6697 -quiet 2>/dev/null | head -8 )
if echo "$BANNER" | grep -qiE 'irc|NOTICE|Welcome|Unreal|^:.* 00[0-9]'; then
    record_poc stunnel_reaches_ircd 1
else
    record_poc stunnel_reaches_ircd 0 "TLS connection on 6697 did not reach an IRC banner -- tunnel or daemon broken"
fi

verify_finish
