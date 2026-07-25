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

# =============================================================================
# PoC Behavioral Test (RUNTIME): ACTUALLY ATTEMPT THE PRIVILEGE ESCALATION.
#
# The `find -perm -4000` checks above only read inode metadata. This block runs
# the real GTFOBins attack as the unprivileged `testuser` and asks the kernel
# what it got:
#
#   * euid must not be 0 when an unprivileged user runs the interpreter
#   * os.setuid(0) must be refused by the kernel
#   * /etc/shadow (root-only, mode 0640 root:shadow) must NOT be readable
#
# Reading /etc/shadow as testuser is the definitive proof of root compromise.
# Nothing here writes to the filesystem.
# =============================================================================
echo ""
echo "[PoC] Attempting REAL privilege escalation as unprivileged user testuser..."

EXPLOIT_FOUND=0

if ! id testuser >/dev/null 2>&1; then
    echo "[PoC] FAIL: testuser is missing -- cannot run the privilege-escalation probe."
    exit 1
fi

# --- python3: effective UID + kernel-enforced setuid(0) + /etc/shadow read ---
if command -v python3 >/dev/null 2>&1; then
    PY_EUID=$(su -s /bin/bash -c "python3 -c 'import os; print(os.geteuid())'" testuser 2>/dev/null | tr -d ' \r')
    if [ "$PY_EUID" = "0" ]; then
        echo "[PoC] FAIL: python3 runs with euid=0 for testuser -- SUID privilege escalation works."
        EXPLOIT_FOUND=1
    else
        echo "[PoC] PASS: python3 runs with euid=$PY_EUID for testuser (not root)."
    fi

    PY_SETUID=$(su -s /bin/bash -c "python3 -c 'import os
try:
    os.setuid(0)
    print(\"SETUID_ROOT_OK\")
except Exception:
    print(\"SETUID_DENIED\")'" testuser 2>/dev/null | tr -d ' \r')
    if [ "$PY_SETUID" = "SETUID_ROOT_OK" ]; then
        echo "[PoC] FAIL: testuser successfully called setuid(0) via python3 -- full root."
        EXPLOIT_FOUND=1
    else
        echo "[PoC] PASS: kernel denied setuid(0) from python3 run by testuser."
    fi

    PY_SHADOW=$(su -s /bin/bash -c "python3 -c '
try:
    open(\"/etc/shadow\").readline()
    print(\"SHADOW_READ_OK\")
except Exception:
    print(\"SHADOW_DENIED\")'" testuser 2>/dev/null | tr -d ' \r')
    if [ "$PY_SHADOW" = "SHADOW_READ_OK" ]; then
        echo "[PoC] FAIL: testuser read /etc/shadow through python3 -- password hashes exposed."
        EXPLOIT_FOUND=1
    else
        echo "[PoC] PASS: testuser cannot read /etc/shadow through python3."
    fi
fi

# --- perl: $> is the effective UID ---
if command -v perl >/dev/null 2>&1; then
    PL_EUID=$(su -s /bin/bash -c 'perl -e "print \$>"' testuser 2>/dev/null | tr -d ' \r')
    if [ "$PL_EUID" = "0" ]; then
        echo "[PoC] FAIL: perl runs with euid=0 for testuser -- SUID privilege escalation works."
        EXPLOIT_FOUND=1
    else
        echo "[PoC] PASS: perl runs with euid=$PL_EUID for testuser (not root)."
    fi

    PL_SHADOW=$(su -s /bin/bash -c 'perl -e "if (open(F, q{/etc/shadow})) { print q{SHADOW_READ_OK} } else { print q{SHADOW_DENIED} }"' testuser 2>/dev/null | tr -d ' \r')
    if [ "$PL_SHADOW" = "SHADOW_READ_OK" ]; then
        echo "[PoC] FAIL: testuser read /etc/shadow through perl -- password hashes exposed."
        EXPLOIT_FOUND=1
    else
        echo "[PoC] PASS: testuser cannot read /etc/shadow through perl."
    fi
fi

# --- Sweep every other SUID interpreter that could grant the same thing ---
for cand in /usr/bin/awk /usr/bin/gawk /usr/bin/mawk /usr/bin/ruby* /usr/bin/php* /usr/bin/perl*; do
    [ -f "$cand" ] || continue
    if find "$cand" -perm -4000 2>/dev/null | grep -q .; then
        echo "[PoC] FAIL: SUID interpreter left behind: $cand (mode: $(stat -c '%a' "$cand"))"
        EXPLOIT_FOUND=1
    fi
done

if [ "$EXPLOIT_FOUND" -eq 1 ]; then
    echo "[PoC] RESULT: Vulnerability still exploitable -- unprivileged user reached root."
    exit 1
fi
echo "[PoC] PASS: privilege escalation to root via the interpreters failed."

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
