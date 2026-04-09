#!/bin/bash
for LOG in /var/log/auth.log /var/log/apache2/access.log; do
    if [ -f "$LOG" ]; then
        PERMS=$(stat -c %a "$LOG" 2>/dev/null)
        if [ "$((PERMS % 10))" -gt 0 ] 2>/dev/null; then
            echo "FAIL [PoC]: $LOG is world-accessible ($PERMS)."; exit 1
        fi
    fi
done
echo "PASS [PoC]: Log files properly restricted."
if pgrep -x apache2 > /dev/null 2>&1; then echo "PASS [Regression]: Apache running."
else echo "FAIL [Regression]: Apache not running."; exit 1; fi
echo "All checks passed."; exit 0
