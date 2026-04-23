#!/bin/bash
cfg=false; live=false

# Config-grep style: getcap inspection of on-disk xattrs
CAPS=$(getcap /usr/bin/python3* /usr/bin/find 2>/dev/null | grep -v '=$')
if [ -n "$CAPS" ]; then
    cfg=true
fi

# Behavioural probe: actually exercise the capabilities as an
# unprivileged user.
#   - cap_dac_read_search on python3 -> can read /etc/shadow
#   - cap_setuid on find           -> can escalate to uid 0 via -exec
# If either works, the capability is still live regardless of xattrs.
if id nobody >/dev/null 2>&1; then
    # Probe DAC bypass: try reading /etc/shadow via python
    for PY in /usr/bin/python3 /usr/bin/python3.7 /usr/bin/python3.8 /usr/bin/python3.9 /usr/bin/python3.10 /usr/bin/python3.11; do
        [ -x "$PY" ] || continue
        if su -s /bin/sh nobody -c "'$PY' -c 'open(\"/etc/shadow\").read(16)' >/dev/null 2>&1"; then
            live=true
            break
        fi
    done
    # Probe setuid escalation via find
    if [ -x /usr/bin/find ]; then
        OUT=$(su -s /bin/sh nobody -c '/usr/bin/find . -maxdepth 0 -exec /usr/bin/id -u \; 2>/dev/null' 2>/dev/null)
        if [ "$OUT" = "0" ]; then
            live=true
        fi
        # Alternative: find -exec can invoke a setuid(0) wrapper; also try
        # direct capability use by having find spawn a shell that checks
        # euid via /proc.
        EUID_OUT=$(su -s /bin/sh nobody -c '/usr/bin/find . -maxdepth 0 -exec sh -c "awk \"/^Uid:/ {print \\\$3}\" /proc/self/status" \; 2>/dev/null' 2>/dev/null)
        if [ "$EUID_OUT" = "0" ]; then
            live=true
        fi
    fi
fi

if $cfg || $live; then
    echo "FAIL [PoC]: Dangerous capabilities still exploitable (cfg=$cfg live=$live)."
    [ -n "$CAPS" ] && echo "$CAPS"
    exit 1
fi
echo "PASS [PoC]: No dangerous capabilities on monitored binaries (cfg=$cfg live=$live)."
echo "All checks passed."; exit 0
