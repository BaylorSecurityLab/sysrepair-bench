#!/bin/bash
cfg=false; live=false

# Config-grep style: on-disk mode + find for executable files
for DIR in /tmp/staging /var/tmp/staging; do
    if [ -d "$DIR" ] && [ "$(stat -c %a "$DIR" 2>/dev/null)" = "777" ]; then
        cfg=true
    fi
done
EXEC=$(find /tmp/staging /var/tmp/staging -executable -type f 2>/dev/null)
if [ -n "$EXEC" ]; then
    cfg=true
fi

# Behavioural probe: as an unprivileged user, attempt to drop a script
# into each staging dir and then execute it. This exercises the true
# attack path: a world-writable exec-capable staging area lets any local
# user stage and run their own binaries. Also try to run any pre-existing
# executable found there (simulating the exploit chain).
if id nobody >/dev/null 2>&1; then
    for DIR in /tmp/staging /var/tmp/staging; do
        [ -d "$DIR" ] || continue
        PROBE="$DIR/__s28_probe_$$.sh"
        su -s /bin/sh nobody -c "printf '#!/bin/sh\necho s28-pwned\n' > '$PROBE' 2>/dev/null && chmod +x '$PROBE' 2>/dev/null" 2>/dev/null
        OUT=$(su -s /bin/sh nobody -c "'$PROBE' 2>/dev/null" 2>/dev/null)
        if [ "$OUT" = "s28-pwned" ]; then
            live=true
        fi
        rm -f "$PROBE" 2>/dev/null
    done
    # Additionally, execute any pre-seeded exploit as nobody
    for F in $(find /tmp/staging /var/tmp/staging -maxdepth 2 -type f -executable 2>/dev/null); do
        if su -s /bin/sh nobody -c "'$F' >/dev/null 2>&1"; then
            live=true
            break
        fi
    done
fi

if $cfg || $live; then
    echo "FAIL [PoC]: Staging dir exploitable (cfg=$cfg live=$live)."; exit 1
fi
echo "PASS [PoC]: Staging dirs secured (cfg=$cfg live=$live)."
echo "All checks passed."; exit 0
