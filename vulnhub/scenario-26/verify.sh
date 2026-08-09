#!/bin/bash
# Scenario 26: sensitive logs must not be world-accessible.
#
# PoC checks:        each sensitive log has no world (other) permission bit, and
#                    an unprivileged user cannot actually read it
# Regression checks: apache is running
#
# Dynamic check: as 'nobody', try to actually read each log - a successful read
# is the real information-disclosure path -> FAIL. Also fail on any world (other)
# permission bit set on the files.
#
# Two-component protocol: nothing aborts early, so "chmod'd the logs but killed
# apache" reports security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(cat /proc/"$pid"/comm 2>/dev/null)" = "apache2" ] && { running=true; break; }
done
if $running; then
    record_reg apache_running 1
else
    record_reg apache_running 0 "apache is not running"
fi

SAW_LOG=0
for LOG in /var/log/auth.log /var/log/apache2/access.log; do
    [ -f "$LOG" ] || continue
    SAW_LOG=1
    TAG=$(printf '%s' "$LOG" | sed 's|^/var/log/||' | sed 's|[^A-Za-z0-9]|_|g')
    P=$(stat -c %a "$LOG" 2>/dev/null)
    last=${P: -1}
    if [ "$(( last ))" -ne 0 ] 2>/dev/null; then
        record_poc "${TAG}_mode_restricted" 0 "$LOG is world-accessible (mode $P)"
    else
        record_poc "${TAG}_mode_restricted" 1
    fi
    if id nobody >/dev/null 2>&1; then
        if timeout 5 su -s /bin/sh nobody -c "head -c 1 '$LOG' >/dev/null 2>&1" 2>/dev/null; then
            record_poc "${TAG}_unreadable_by_nobody" 0 "unprivileged user can read $LOG"
        else
            record_poc "${TAG}_unreadable_by_nobody" 1
        fi
    fi
done

if [ "$SAW_LOG" -eq 0 ]; then
    record_poc sensitive_logs_present 0 "neither /var/log/auth.log nor /var/log/apache2/access.log exists - cannot evaluate the exposure"
fi

verify_finish
