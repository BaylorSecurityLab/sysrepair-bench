#!/bin/bash
cfg=false; live=false

# Config-grep style: grep cron files for /tmp paths run as root
if grep -r '/tmp/' /etc/cron* /var/spool/cron 2>/dev/null | grep -v '^#' | grep -q 'root'; then
    cfg=true
fi

# Behavioural probe: confirm the cron daemon is actually running AND that
# an unprivileged user can replace the scripts referenced from root cron
# entries. This is the live attack path: cron is scheduled, the target
# script is world-writable, so the attacker can overwrite it for root
# code execution on the next tick.
if pgrep -x cron >/dev/null 2>&1 || pgrep -x crond >/dev/null 2>&1; then
    # Collect every /tmp path referenced by any root cron line
    TARGETS=$(grep -rhE '^[^#].*root.*(/tmp/[^ ]+)' /etc/cron* /var/spool/cron 2>/dev/null \
        | grep -oE '/tmp/[^ ]+' | sort -u)
    if [ -n "$TARGETS" ] && id nobody >/dev/null 2>&1; then
        for T in $TARGETS; do
            if su -s /bin/sh nobody -c "[ -w '$T' ] || [ -w \"\$(dirname '$T')\" ]" 2>/dev/null; then
                live=true
                break
            fi
        done
    fi
fi

if $cfg || $live; then
    echo "FAIL [PoC]: Root cron -> /tmp hijack path (cfg=$cfg live=$live)."; exit 1
fi
echo "PASS [PoC]: No root cron entries reference /tmp (cfg=$cfg live=$live)."
echo "All checks passed."; exit 0
