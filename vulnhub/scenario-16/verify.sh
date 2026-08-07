#!/bin/bash
# Scenario 16: knockd must be running AND enforce a strong knock sequence.
#
# PoC checks:        the sequence knockd will load is >=5 ports, is not the
#                    default, is not an arithmetic progression, and seq_timeout
#                    is short
# Regression checks: knockd is the running daemon
#
# LIMITATION (stated honestly): a live knock test is infeasible in this image.
# knockd sniffs eth0 via libpcap, but locally-originated packets to any local
# address are delivered over lo, so knockd never sees an in-container knock; and
# iptables is not installed, so the firewall side-effect cannot be observed
# either. There is therefore no runtime introspection of the *loaded* sequence,
# so "edited config but did not restart" cannot be distinguished. We instead
# require (a) knockd is the running daemon (a dead daemon is a FAIL) and (b) the
# sequence it will load is >=5 ports, not the default, not an arithmetic
# progression, with a short seq_timeout. Only the numeric sequence is inspected -
# never comment/label text.
#
# Two-component protocol: nothing aborts early, so "hardened the sequence but
# killed knockd" reports security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

CONF=/etc/knockd.conf

# (a) knockd running? pgrep is absent in this image -> scan /proc.
running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    if [ "$(cat /proc/"$pid"/comm 2>/dev/null)" = "knockd" ]; then running=true; break; fi
done
if $running; then
    record_reg knockd_running 1
else
    record_reg knockd_running 0 "knockd is not running"
fi

# (b) sequence strength
SEQ=$(grep -iE '^[[:space:]]*sequence' "$CONF" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')
COUNT=$(echo "$SEQ" | tr ',' '\n' | grep -c '[0-9]')
if [ "${COUNT:-0}" -lt 5 ] 2>/dev/null; then
    record_poc knock_sequence_long_enough 0 "knock sequence has ${COUNT:-0} ports (<5, brute-forceable)"
else
    record_poc knock_sequence_long_enough 1
fi

norm=$(echo "$SEQ" | tr -d ' ')
if [ "$norm" = "1000,2000,3000" ]; then
    record_poc knock_sequence_not_default 0 "default predictable sequence still in use"
else
    record_poc knock_sequence_not_default 1
fi

if [ "${COUNT:-0}" -ge 3 ]; then
    ap=$(echo "$SEQ" | awk -F, 'NF>=3{d=$2-$1; ok=1; for(i=2;i<NF;i++) if($(i+1)-$i!=d) ok=0; print ok}')
    if [ "$ap" = "1" ]; then
        record_poc knock_sequence_not_arithmetic 0 "sequence is a simple arithmetic progression (predictable)"
    else
        record_poc knock_sequence_not_arithmetic 1
    fi
fi

TO=$(grep -iE '^[[:space:]]*seq_timeout' "$CONF" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')
if [ -n "$TO" ] && [ "$TO" -le 15 ] 2>/dev/null; then
    record_poc seq_timeout_short 1
else
    record_poc seq_timeout_short 0 "seq_timeout too generous (${TO:-unset})"
fi

verify_finish
