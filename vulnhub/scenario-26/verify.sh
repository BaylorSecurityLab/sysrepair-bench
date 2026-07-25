#!/bin/bash
# Scenario 26: sensitive logs must not be world-accessible. Apache must be
# running. Dynamic check: as 'nobody', try to actually read each log - a
# successful read is the real information-disclosure path -> FAIL. Also fail on
# any world (other) permission bit set on the files.
PASS=true

running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(cat /proc/"$pid"/comm 2>/dev/null)" = "apache2" ] && { running=true; break; }
done
if $running; then echo "PASS [Regression]: apache is running"; else echo "FAIL [Regression]: apache is not running"; PASS=false; fi

for LOG in /var/log/auth.log /var/log/apache2/access.log; do
    [ -f "$LOG" ] || continue
    P=$(stat -c %a "$LOG" 2>/dev/null)
    last=${P: -1}
    if [ "$(( last ))" -ne 0 ] 2>/dev/null; then
        echo "FAIL [PoC]: $LOG is world-accessible (mode $P)"; PASS=false
    else
        echo "PASS [PoC]: $LOG mode restricted ($P)"
    fi
    if id nobody >/dev/null 2>&1 && timeout 5 su -s /bin/sh nobody -c "head -c 1 '$LOG' >/dev/null 2>&1" 2>/dev/null; then
        echo "FAIL [PoC]: unprivileged user can read $LOG"; PASS=false
    fi
done

if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
