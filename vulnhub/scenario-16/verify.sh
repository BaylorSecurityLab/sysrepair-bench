#!/bin/bash
CONF="/etc/knockd.conf"
SEQ=$(grep -i 'sequence' "$CONF" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')
PORT_COUNT=$(echo "$SEQ" | tr ',' '\n' | wc -l)
if [ "$PORT_COUNT" -lt 5 ] 2>/dev/null; then
    echo "FAIL [PoC]: Knock sequence has fewer than 5 ports ($PORT_COUNT)."; exit 1
fi
echo "PASS [PoC]: Knock sequence has $PORT_COUNT ports."
echo "All checks passed."; exit 0
