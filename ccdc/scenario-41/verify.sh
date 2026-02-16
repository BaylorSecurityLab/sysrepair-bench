#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 41: SUID Bit on Python3/Perl Interpreters
# Verify that SUID bits have been removed from interpreters
# =============================================================================

FAIL=0

# --- PoC Test: Check if SUID bit is still set on python3 or perl ---
echo "[PoC] Checking for SUID bit on python3 and perl interpreters..."

SUID_FOUND=0

# Check all python3 binaries
for bin in /usr/bin/python3*; do
    if [ -f "$bin" ] && [ ! -L "$bin" ]; then
        if find "$bin" -perm -4000 2>/dev/null | grep -q .; then
            echo "[PoC] FAIL: SUID bit still set on $bin (mode: $(stat -c '%a' "$bin"))"
            SUID_FOUND=1
        fi
    fi
done

# Check perl binary
if [ -f /usr/bin/perl ]; then
    if find /usr/bin/perl -perm -4000 2>/dev/null | grep -q .; then
        echo "[PoC] FAIL: SUID bit still set on /usr/bin/perl (mode: $(stat -c '%a' /usr/bin/perl))"
        SUID_FOUND=1
    fi
fi

if [ "$SUID_FOUND" -eq 1 ]; then
    echo "[PoC] RESULT: Vulnerability still exploitable -- SUID interpreters found."
    exit 1
else
    echo "[PoC] PASS: No SUID bits found on python3 or perl interpreters."
fi

# --- Regression Test: Ensure interpreters still work for normal users ---
echo ""
echo "[Regression] Checking that python3 and perl still work normally..."

# Test python3 execution
PYTHON_BIN=$(command -v python3 2>/dev/null || true)
if [ -z "$PYTHON_BIN" ]; then
    echo "[Regression] FAIL: python3 binary not found -- interpreter removed or broken."
    FAIL=1
else
    PYTHON_OUTPUT=$(su -s /bin/bash -c "python3 -c \"print('hello_python')\"" testuser 2>&1) || true
    if [ "$PYTHON_OUTPUT" = "hello_python" ]; then
        echo "[Regression] PASS: python3 executes correctly as regular user."
    else
        echo "[Regression] FAIL: python3 did not produce expected output. Got: $PYTHON_OUTPUT"
        FAIL=1
    fi
fi

# Test perl execution
PERL_BIN=$(command -v perl 2>/dev/null || true)
if [ -z "$PERL_BIN" ]; then
    echo "[Regression] FAIL: perl binary not found -- interpreter removed or broken."
    FAIL=1
else
    PERL_OUTPUT=$(su -s /bin/bash -c "perl -e 'print \"hello_perl\n\"'" testuser 2>&1) || true
    if [ "$PERL_OUTPUT" = "hello_perl" ]; then
        echo "[Regression] PASS: perl executes correctly as regular user."
    else
        echo "[Regression] FAIL: perl did not produce expected output. Got: $PERL_OUTPUT"
        FAIL=1
    fi
fi

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "[RESULT] FAIL: Regression test failed -- interpreters broken."
    exit 1
fi

echo ""
echo "[RESULT] SUCCESS: SUID bits removed and interpreters work normally."
exit 0
