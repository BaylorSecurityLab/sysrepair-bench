#!/bin/bash
# Scenario 28: staging dirs must not be world-writable exec areas.
#
# PoC checks:        no staging dir is 777, no world-writable file lives under
#                    them, and an unprivileged user cannot stage and run code
#
# Dynamic check: as 'nobody', actually try to drop a script into each staging
# dir, mark it executable and run it - success is the real attack path (stage +
# run arbitrary code) -> FAIL. Also fail on a 777 dir or any world-writable file.
#
# There is no service in this scenario (no .preserve-cmd) and no regression
# check: the finding is purely directory-permission state, so regression_pass is
# reported as null rather than as a vacuous true. See lib/verifylib.sh.
#
# Two-component protocol: nothing aborts early.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

for DIR in /tmp/staging /var/tmp/staging; do
    [ -d "$DIR" ] || continue
    TAG=$(printf '%s' "$DIR" | sed 's|^/||' | sed 's|[^A-Za-z0-9]|_|g')
    P=$(stat -c %a "$DIR" 2>/dev/null)
    if [ "$P" = "777" ]; then
        record_poc "${TAG}_not_world_writable" 0 "$DIR is world-writable (777)"
    else
        record_poc "${TAG}_not_world_writable" 1
    fi
done

WW=$(find /tmp/staging /var/tmp/staging -type f -perm -o+w 2>/dev/null)
if [ -n "$WW" ]; then
    record_poc staging_no_world_writable_files 0 "world-writable files in staging: $(printf '%s' "$WW" | tr '\n' ' ')"
else
    record_poc staging_no_world_writable_files 1
fi

if id nobody >/dev/null 2>&1; then
    for DIR in /tmp/staging /var/tmp/staging; do
        [ -d "$DIR" ] || continue
        TAG=$(printf '%s' "$DIR" | sed 's|^/||' | sed 's|[^A-Za-z0-9]|_|g')
        P="$DIR/__s28_probe_$$.sh"
        OUT=$(timeout 5 su -s /bin/sh nobody -c "printf '#!/bin/sh\necho S28PWN\n' > '$P' 2>/dev/null && chmod +x '$P' 2>/dev/null && '$P'" 2>/dev/null)
        rm -f "$P" 2>/dev/null
        if [ "$OUT" = "S28PWN" ]; then
            record_poc "${TAG}_stage_and_exec_denied" 0 "unprivileged user staged and executed code in $DIR"
        else
            record_poc "${TAG}_stage_and_exec_denied" 1
        fi
    done
fi

verify_finish
