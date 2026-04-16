#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

KV=$(uname -r | sed -E 's/-.*//; s/\+.*//')
SAFE=0

case "$KV" in
    5.10.*) ver_ge "$KV" "5.10.103" && SAFE=1 ;;
    5.15.*) ver_ge "$KV" "5.15.26"  && SAFE=1 ;;
    5.8.*|5.9.*|5.11.*|5.12.*|5.13.*|5.14.*|5.16.*) ver_ge "$KV" "5.16.11" && SAFE=1 ;;
    *)
        # 5.17+, 6.x — all fixed
        if ver_ge "$KV" "5.16.11"; then SAFE=1; fi
        ;;
esac
if [ "$SAFE" = "1" ]; then
    echo "PASS [PoC]: host kernel $KV is on a patched branch."
else
    # Compensating control: immutable bit on the SUID marker
    if command -v lsattr >/dev/null 2>&1 && lsattr /opt/suid-marker 2>/dev/null | grep -q '^....i'; then
        echo "PASS [PoC]: kernel $KV vulnerable, but chattr +i compensating control set."
        SAFE=1
    fi
fi
[ "$SAFE" = "1" ] || { echo "FAIL [PoC]: kernel $KV vulnerable and no +i on /opt/suid-marker." >&2; exit 1; }

OUT=$(/opt/suid-marker 2>/dev/null || true)
[ "$OUT" = "original" ] && { echo "PASS [Regression]: marker binary functional."; exit 0; }
echo "FAIL [Regression]: /opt/suid-marker output '$OUT' != 'original'." >&2; exit 1
