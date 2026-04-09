#!/bin/bash
WW=$(find /var/www -perm -o+w -type f 2>/dev/null | head -5)
if [ -n "$WW" ]; then
    echo "FAIL [PoC]: World-writable files in /var/www found."; exit 1
fi
echo "PASS [PoC]: No world-writable files in /var/www."
echo "All checks passed."; exit 0
