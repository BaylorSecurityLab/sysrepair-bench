#!/bin/bash
cfg=false; live=false

# Config-grep style: on-disk mode inspection
if stat -c %A /usr/local/bin/statuscheck 2>/dev/null | grep -q 's'; then
    cfg=true
fi

# Behavioural probe: invoke statuscheck as an unprivileged user and
# observe the effective uid of its child (/proc inspection). With SUID
# set, system("curl ...") runs under euid=0; without SUID, euid matches
# the caller. We spawn the binary under `nobody` and snapshot /proc.
if id nobody >/dev/null 2>&1 && [ -x /usr/local/bin/statuscheck ]; then
    # Run in the background under nobody, then immediately snapshot any
    # child of the invoked binary from /proc/*/status
    (
        su -s /bin/sh nobody -c '/usr/local/bin/statuscheck >/dev/null 2>&1 &
            echo $! > /tmp/.s23.pid
            wait' &
    ) 2>/dev/null
    sleep 1
    # Walk every process and find any whose exe path points at statuscheck
    # or whose parent is it; read their effective uid.
    for p in /proc/[0-9]*; do
        EXE=$(readlink "$p/exe" 2>/dev/null)
        CMD=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
        case "$EXE$CMD" in
            */statuscheck*|*curl*localhost/status*)
                EUID_LIVE=$(awk '/^Uid:/ {print $3}' "$p/status" 2>/dev/null)
                RUID_LIVE=$(awk '/^Uid:/ {print $2}' "$p/status" 2>/dev/null)
                if [ -n "$EUID_LIVE" ] && [ "$EUID_LIVE" = "0" ] && [ "$RUID_LIVE" != "0" ]; then
                    live=true
                fi
                ;;
        esac
    done
    # Cleanup
    [ -f /tmp/.s23.pid ] && kill "$(cat /tmp/.s23.pid)" 2>/dev/null
    rm -f /tmp/.s23.pid 2>/dev/null
fi

if $cfg || $live; then
    echo "FAIL [PoC]: statuscheck SUID still active (cfg=$cfg live=$live)."; exit 1
fi
echo "PASS [PoC]: SUID bit removed from statuscheck (cfg=$cfg live=$live)."
echo "All checks passed."; exit 0
