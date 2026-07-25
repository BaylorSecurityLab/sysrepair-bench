#!/bin/bash
# Scenario 16: knockd must be running AND enforce a strong knock sequence.
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
CONF=/etc/knockd.conf
PASS=true

# (a) knockd running? pgrep is absent in this image -> scan /proc.
running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    if [ "$(cat /proc/"$pid"/comm 2>/dev/null)" = "knockd" ]; then running=true; break; fi
done
if $running; then echo "PASS [Regression]: knockd is running"; else echo "FAIL [Regression]: knockd is not running"; PASS=false; fi

# (b) sequence strength
SEQ=$(grep -iE '^[[:space:]]*sequence' "$CONF" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')
COUNT=$(echo "$SEQ" | tr ',' '\n' | grep -c '[0-9]')
if [ "${COUNT:-0}" -lt 5 ] 2>/dev/null; then
    echo "FAIL [PoC]: knock sequence has ${COUNT:-0} ports (<5, brute-forceable)"; PASS=false
else
    echo "PASS [PoC]: knock sequence length ${COUNT}"
fi

norm=$(echo "$SEQ" | tr -d ' ')
if [ "$norm" = "1000,2000,3000" ]; then
    echo "FAIL [PoC]: default predictable sequence still in use"; PASS=false
fi

if [ "${COUNT:-0}" -ge 3 ]; then
    ap=$(echo "$SEQ" | awk -F, 'NF>=3{d=$2-$1; ok=1; for(i=2;i<NF;i++) if($(i+1)-$i!=d) ok=0; print ok}')
    if [ "$ap" = "1" ]; then echo "FAIL [PoC]: sequence is a simple arithmetic progression (predictable)"; PASS=false; fi
fi

TO=$(grep -iE '^[[:space:]]*seq_timeout' "$CONF" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')
if [ -n "$TO" ] && [ "$TO" -le 15 ] 2>/dev/null; then
    echo "PASS [PoC]: seq_timeout=$TO"
else
    echo "FAIL [PoC]: seq_timeout too generous (${TO:-unset})"; PASS=false
fi

if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
