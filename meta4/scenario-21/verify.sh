#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

KV=$(uname -r | sed -E 's/-.*//')
SAFE=0

# Rough fixed lines: 5.15.0-75, 5.19.0-46, 6.2.0-26, or any 6.3+
case "$KV" in
    5.15.*) ver_ge "$KV" "5.15.0" && [ "$(uname -r | grep -oE -- '-[0-9]+' | head -1 | tr -d -)" -ge 75 2>/dev/null ] && SAFE=1 ;;
    5.19.*) [ "$(uname -r | grep -oE -- '-[0-9]+' | head -1 | tr -d -)" -ge 46 2>/dev/null ] && SAFE=1 ;;
    6.2.*)  [ "$(uname -r | grep -oE -- '-[0-9]+' | head -1 | tr -d -)" -ge 26 2>/dev/null ] && SAFE=1 ;;
    *) ver_ge "$KV" "6.3" && SAFE=1 ;;
esac

if [ "$SAFE" = "1" ]; then
    echo "PASS [PoC]: host kernel $(uname -r) is on a patched line."
else
    # Compensating control
    UC=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "")
    if [ "$UC" = "0" ]; then
        echo "PASS [PoC]: kernel $(uname -r) vulnerable, but unprivileged_userns_clone=0."
        SAFE=1
    fi
fi
[ "$SAFE" = "1" ] || { echo "FAIL [PoC]: kernel $(uname -r) vulnerable and user namespaces not restricted." >&2; exit 1; }

/opt/marker-bash -c 'exit 0' && { echo "PASS [Regression]: marker-bash executes."; exit 0; }
echo "FAIL [Regression]: marker-bash broken." >&2; exit 1
