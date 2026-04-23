#!/bin/bash
# Verification: Scenario 19 - Screen SUID (DC-5)
cfg=false; live=false

# Config-grep style: on-disk mode bits
if stat -c %A /usr/bin/screen 2>/dev/null | grep -q 's'; then
    cfg=true
fi

# Behavioural probe: as unprivileged user, invoke screen and observe the
# effective uid it runs under via /proc. With SUID set, screen's process
# image shows Uid: 1000 0 0 0 (euid=0). With SUID cleared, euid matches
# the invoking user.
if id nobody >/dev/null 2>&1 && command -v screen >/dev/null 2>&1; then
    OUT=$(su -s /bin/sh nobody -c '
        (screen -D -m -S probe_s12 sleep 5 >/dev/null 2>&1 &)
        sleep 1
        for p in $(pgrep -x screen 2>/dev/null); do
            grep -E "^Uid:" /proc/$p/status 2>/dev/null
        done
        pkill -x screen 2>/dev/null
    ' 2>/dev/null)
    # Look for euid=0 (second field) while real uid != 0
    if echo "$OUT" | awk '/^Uid:/ { if ($2 != 0 && $3 == 0) print "SUID_ACTIVE" }' | grep -q SUID_ACTIVE; then
        live=true
    fi
fi

if $cfg || $live; then
    echo "FAIL [PoC]: Screen SUID still present (cfg=$cfg live=$live)."; exit 1
fi
echo "PASS [PoC]: Screen SUID bit removed (cfg=$cfg live=$live)."
echo "All checks passed."; exit 0
