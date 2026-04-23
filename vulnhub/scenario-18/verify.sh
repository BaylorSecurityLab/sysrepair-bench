#!/bin/bash
cfg=false; live=false

# Config-grep style: file-mode inspection
WW=$(find /var/www -perm -o+w -type f 2>/dev/null | head -5)
if [ -n "$WW" ]; then
    cfg=true
fi

# Behavioural probe: as an unprivileged user, actually attempt to drop a
# payload into the webroot and fetch it back via HTTP. This exercises the
# real attack path (unauthenticated remote write via a permissive share
# or mis-owned webroot). We also attempt to overwrite the index.html to
# confirm world-write on existing served files.
PROBE="/var/www/html/__s18_probe_$$.html"
if id nobody >/dev/null 2>&1; then
    su -s /bin/sh nobody -c "echo 's18-pwned' > '$PROBE' 2>/dev/null" 2>/dev/null
    if [ -f "$PROBE" ]; then
        live=true
        # If apache is up, verify the file is actually reachable
        if command -v curl >/dev/null 2>&1; then
            curl -fsS "http://127.0.0.1/$(basename "$PROBE")" 2>/dev/null | grep -q 's18-pwned' && live=true
        fi
        rm -f "$PROBE" 2>/dev/null
    fi
    # Also test overwrite of an existing served file's permissions
    if [ -f /var/www/html/index.html ] && su -s /bin/sh nobody -c '[ -w /var/www/html/index.html ]' 2>/dev/null; then
        live=true
    fi
fi

if $cfg || $live; then
    echo "FAIL [PoC]: /var/www world-writable exposure (cfg=$cfg live=$live)."; exit 1
fi
echo "PASS [PoC]: No world-writable exposure in /var/www (cfg=$cfg live=$live)."
echo "All checks passed."; exit 0
