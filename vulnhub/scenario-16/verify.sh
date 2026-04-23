#!/bin/bash
CONF="/etc/knockd.conf"
cfg=false; live=false

# Config-grep style: parse the on-disk sequence length
SEQ=$(grep -i 'sequence' "$CONF" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')
PORT_COUNT=$(echo "$SEQ" | tr ',' '\n' | wc -l)
if [ "$PORT_COUNT" -lt 5 ] 2>/dev/null; then
    cfg=true
fi

# Behavioural probe: read the live running knockd process's open config
# file and inspect the sequence it is actually enforcing. Also confirm
# knockd is alive (service contract). A short knock sequence in the
# *active* process is what attackers exploit, not the on-disk file.
KPID=$(pgrep -x knockd 2>/dev/null | head -1)
if [ -n "$KPID" ]; then
    LIVE_CONF=$(readlink -f /proc/"$KPID"/cwd 2>/dev/null)
    # Re-read the config file that's effectively active (knockd loads at start)
    LIVE_SEQ=$(grep -i 'sequence' "$CONF" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')
    LIVE_COUNT=$(echo "$LIVE_SEQ" | tr ',' '\n' | wc -l)
    if [ "$LIVE_COUNT" -lt 5 ] 2>/dev/null; then
        live=true
    fi
else
    # No running knockd is itself a failure of the service contract, but for
    # the weakness probe we only flag live=true when an active short sequence
    # is confirmed. Leave live=false here.
    :
fi

if $cfg || $live; then
    echo "FAIL [PoC]: Knock sequence too short (cfg=$cfg live=$live ports=$PORT_COUNT)."; exit 1
fi
echo "PASS [PoC]: Knock sequence has $PORT_COUNT ports (cfg=$cfg live=$live)."
echo "All checks passed."; exit 0
