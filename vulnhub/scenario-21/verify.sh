#!/bin/bash
# Scenario 21: no root cron entry may execute a script from a world-writable
# location.
#
# PoC checks:        no root cron line references /tmp or /var/tmp, and no script
#                    a root cron line runs is writable by an unprivileged user
# Regression checks: cron is running
#
# cron must be running (dead scheduler = FAIL). Dynamic check: for every script
# path referenced by a root cron line, verify that neither the file nor its
# directory is writable by an unprivileged user (the real hijack path). Also fail
# outright on any root cron line still pointing into /tmp or /var/tmp.
#
# Two-component protocol: nothing aborts early, so "moved the cron scripts but
# killed cron" reports security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# cron running? pgrep is absent -> scan /proc.
running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    c=$(cat /proc/"$pid"/comm 2>/dev/null)
    if [ "$c" = "cron" ] || [ "$c" = "crond" ]; then running=true; break; fi
done
if $running; then
    record_reg cron_running 1
else
    record_reg cron_running 0 "cron is not running"
fi

CRONSRC="/etc/cron.d /etc/crontab /etc/cron.hourly /etc/cron.daily"
# any root cron line referencing /tmp or /var/tmp is an immediate FAIL
if grep -rhE '^[^#].*root.*(/tmp/|/var/tmp/)' $CRONSRC 2>/dev/null | grep -q .; then
    record_poc no_root_cron_in_tmp 0 "root cron entry still references /tmp or /var/tmp"
else
    record_poc no_root_cron_in_tmp 1
fi

# collect script paths from root cron lines and probe writability as nobody
TARGETS=$(grep -rhE '^[^#].*[[:space:]]root[[:space:]]' $CRONSRC 2>/dev/null \
    | grep -oE '/[A-Za-z0-9._/-]+\.(sh|py|pl|bash)' | sort -u)
WRITABLE=""
if [ -n "$TARGETS" ] && id nobody >/dev/null 2>&1; then
    for T in $TARGETS; do
        if timeout 5 su -s /bin/sh nobody -c "{ [ -e '$T' ] && [ -w '$T' ]; } || [ -w \"\$(dirname '$T')\" ]" 2>/dev/null; then
            WRITABLE="$WRITABLE $T"
        fi
    done
fi
if [ -n "$WRITABLE" ]; then
    record_poc root_cron_targets_not_writable 0 "root cron target(s) writable by unprivileged user:$WRITABLE"
else
    record_poc root_cron_targets_not_writable 1
fi

verify_finish
