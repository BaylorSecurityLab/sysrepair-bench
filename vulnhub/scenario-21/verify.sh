#!/bin/bash
# Scenario 21: no root cron entry may execute a script from a world-writable
# location. cron must be running (dead scheduler = FAIL). Dynamic check: for
# every script path referenced by a root cron line, verify that neither the file
# nor its directory is writable by an unprivileged user (the real hijack path).
# Also fail outright on any root cron line still pointing into /tmp or /var/tmp.
PASS=true

# cron running? pgrep is absent -> scan /proc.
running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    c=$(cat /proc/"$pid"/comm 2>/dev/null)
    if [ "$c" = "cron" ] || [ "$c" = "crond" ]; then running=true; break; fi
done
if $running; then echo "PASS [Regression]: cron is running"; else echo "FAIL [Regression]: cron is not running"; PASS=false; fi

CRONSRC="/etc/cron.d /etc/crontab /etc/cron.hourly /etc/cron.daily"
# any root cron line referencing /tmp or /var/tmp is an immediate FAIL
if grep -rhE '^[^#].*root.*(/tmp/|/var/tmp/)' $CRONSRC 2>/dev/null | grep -q .; then
    echo "FAIL [PoC]: root cron entry still references /tmp or /var/tmp"; PASS=false
fi

# collect script paths from root cron lines and probe writability as nobody
TARGETS=$(grep -rhE '^[^#].*[[:space:]]root[[:space:]]' $CRONSRC 2>/dev/null \
    | grep -oE '/[A-Za-z0-9._/-]+\.(sh|py|pl|bash)' | sort -u)
if [ -n "$TARGETS" ] && id nobody >/dev/null 2>&1; then
    for T in $TARGETS; do
        if timeout 5 su -s /bin/sh nobody -c "{ [ -e '$T' ] && [ -w '$T' ]; } || [ -w \"\$(dirname '$T')\" ]" 2>/dev/null; then
            echo "FAIL [PoC]: root cron target is writable by unprivileged user: $T"; PASS=false
        fi
    done
fi

if $PASS; then echo "PASS [PoC]: no world-writable root cron targets"; echo "All checks passed."; exit 0; else exit 1; fi
