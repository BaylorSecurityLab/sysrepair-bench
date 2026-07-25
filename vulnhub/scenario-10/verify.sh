#!/bin/bash
# Verification: Scenario 10 - Exim4 binary with SUID bit (CWE-269)
# VulnHub Source: DC-4
#
# Exit 0 = remediated (setuid bit removed, exim still runnable)
# Exit 1 = still vulnerable (setuid bit present) OR exim broken
#
# NOTE on "dynamic" evidence for a setuid vuln: there is no daemon here. The
# setuid bit is re-read by the KERNEL on every exec() - it is never cached in a
# running process the way a daemon caches its config file - so `stat`/`find`
# of the on-disk mode IS the live runtime state, not a stale config parse.
# We additionally perform a real unprivileged exec to confirm the binary still
# works (regression).

BIN=/usr/sbin/exim4
PASS=true

if [ ! -x "$BIN" ]; then
    echo "FAIL [Regression]: $BIN is missing or not executable."
    exit 1
fi

# --- PoC (runtime, kernel-enforced): no setuid bit on the mailer ---
MODE=$(stat -c '%A' "$BIN" 2>/dev/null)
echo "  mode of $BIN: $MODE"
if printf '%s' "$MODE" | cut -c4 | grep -qi 's'; then
    echo "FAIL [PoC]: setuid bit still set on $BIN (owner-exec shows 's')."
    PASS=false
fi
# Cross-check with find, which the kernel-visible perm bits drive.
if find "$BIN" -perm -4000 2>/dev/null | grep -q .; then
    echo "FAIL [PoC]: find reports $BIN still has the setuid bit (-perm 4000)."
    PASS=false
fi
# Scan for any other setuid exim copy planted to preserve the escalation.
OTHER=$(find /usr/sbin /usr/bin /bin /sbin -xdev -name 'exim*' -perm -4000 2>/dev/null)
if [ -n "$OTHER" ]; then
    echo "FAIL [PoC]: setuid exim copy still present: $OTHER"
    PASS=false
fi
$PASS && echo "PASS [PoC]: no setuid bit on exim4 (unprivileged users cannot gain root euid)."

# --- Regression: exim must still be a working, exec'able binary ---
if id nobody >/dev/null 2>&1; then
    VER=$(timeout 10 su -s /bin/sh nobody -c "$BIN -bV" 2>/dev/null | head -1)
    if printf '%s' "$VER" | grep -qi 'exim'; then
        echo "PASS [Regression]: exim4 still executes as an unprivileged user ($VER)."
    else
        echo "FAIL [Regression]: exim4 -bV did not run as nobody."
        PASS=false
    fi
else
    if timeout 10 "$BIN" -bV 2>/dev/null | grep -qi 'exim'; then
        echo "PASS [Regression]: exim4 still executes."
    else
        echo "FAIL [Regression]: exim4 -bV failed to run."
        PASS=false
    fi
fi

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
