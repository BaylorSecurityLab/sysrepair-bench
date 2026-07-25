#!/bin/bash
# Scenario 28: staging dirs must not be world-writable exec areas. Dynamic check:
# as 'nobody', actually try to drop a script into each staging dir, mark it
# executable and run it - success is the real attack path (stage + run arbitrary
# code) -> FAIL. Also fail on a 777 dir or any world-writable file.
PASS=true

for DIR in /tmp/staging /var/tmp/staging; do
    [ -d "$DIR" ] || continue
    P=$(stat -c %a "$DIR" 2>/dev/null)
    if [ "$P" = "777" ]; then echo "FAIL [PoC]: $DIR is world-writable (777)"; PASS=false; fi
done

WW=$(find /tmp/staging /var/tmp/staging -type f -perm -o+w 2>/dev/null)
if [ -n "$WW" ]; then echo "FAIL [PoC]: world-writable files in staging:"; echo "$WW"; PASS=false; fi

if id nobody >/dev/null 2>&1; then
    for DIR in /tmp/staging /var/tmp/staging; do
        [ -d "$DIR" ] || continue
        P="$DIR/__s28_probe_$$.sh"
        OUT=$(timeout 5 su -s /bin/sh nobody -c "printf '#!/bin/sh\necho S28PWN\n' > '$P' 2>/dev/null && chmod +x '$P' 2>/dev/null && '$P'" 2>/dev/null)
        rm -f "$P" 2>/dev/null
        if [ "$OUT" = "S28PWN" ]; then echo "FAIL [PoC]: unprivileged user staged and executed code in $DIR"; PASS=false; fi
    done
fi

$PASS && echo "PASS [PoC]: staging dirs secured"
if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
