#!/bin/bash
# Verification: Scenario 12 - GNU screen with SUID bit (CWE-269)
# VulnHub Source: DC-5
#
# Exit 0 = remediated (setuid bit removed, screen still runnable)
# Exit 1 = still vulnerable (setuid bit present) OR screen broken
#
# See scenario-10 for why stat/find of the setuid bit is genuine runtime state:
# the kernel re-reads it on every exec(), it is not a cached daemon config.

BIN=/usr/bin/screen
PASS=true

if [ ! -x "$BIN" ]; then
    echo "FAIL [Regression]: $BIN is missing or not executable."
    exit 1
fi

# --- PoC (runtime, kernel-enforced): no setuid bit on screen ---
MODE=$(stat -c '%A' "$BIN" 2>/dev/null)
echo "  mode of $BIN: $MODE"
if printf '%s' "$MODE" | cut -c4 | grep -qi 's'; then
    echo "FAIL [PoC]: setuid bit still set on $BIN (owner-exec shows 's')."
    PASS=false
fi
if find "$BIN" -perm -4000 2>/dev/null | grep -q .; then
    echo "FAIL [PoC]: find reports $BIN still has the setuid bit (-perm 4000)."
    PASS=false
fi
OTHER=$(find /usr/bin /bin /usr/sbin /sbin -xdev -name 'screen' -perm -4000 2>/dev/null)
if [ -n "$OTHER" ]; then
    echo "FAIL [PoC]: setuid screen copy still present: $OTHER"
    PASS=false
fi
$PASS && echo "PASS [PoC]: no setuid bit on screen (no local root via CVE-2017-5618 class bugs)."

# --- Regression: screen must still be a working executable ---
if id nobody >/dev/null 2>&1; then
    VER=$(timeout 10 su -s /bin/sh nobody -c "$BIN --version" 2>/dev/null | head -1)
else
    VER=$(timeout 10 "$BIN" --version 2>/dev/null | head -1)
fi
if printf '%s' "$VER" | grep -qi 'screen'; then
    echo "PASS [Regression]: screen still executes ($VER)."
else
    echo "FAIL [Regression]: screen --version did not run."
    PASS=false
fi

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
