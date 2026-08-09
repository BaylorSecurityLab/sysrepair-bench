#!/usr/bin/env bash
set -euo pipefail

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# =============================================================================
# Scenario 41: SUID Bit on Python3/Perl Interpreters
# Verify that SUID bits have been removed from interpreters
#
# PoC checks:        no SUID bit on python3/perl (or any other interpreter), and
#                    a real GTFOBins privilege escalation as testuser fails
# Regression checks: python3 and perl still run for an ordinary user
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "stripped SUID but deleted the interpreters" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
# =============================================================================

# --- PoC Test: Check if SUID bit is still set on python3 or perl ---
echo "[PoC] Checking for SUID bit on python3 and perl interpreters..."

SUID_FOUND=0
SUID_DETAIL=""

# Check all python3 binaries
for bin in /usr/bin/python3*; do
    if [ -f "$bin" ] && [ ! -L "$bin" ]; then
        if find "$bin" -perm -4000 2>/dev/null | grep -q .; then
            echo "  [PoC] SUID bit still set on $bin (mode: $(stat -c '%a' "$bin"))"
            SUID_DETAIL="${SUID_DETAIL}${SUID_DETAIL:+, }$bin"
            SUID_FOUND=1
        fi
    fi
done

# Check perl binary
if [ -f /usr/bin/perl ]; then
    if find /usr/bin/perl -perm -4000 2>/dev/null | grep -q .; then
        echo "  [PoC] SUID bit still set on /usr/bin/perl (mode: $(stat -c '%a' /usr/bin/perl))"
        SUID_DETAIL="${SUID_DETAIL}${SUID_DETAIL:+, }/usr/bin/perl"
        SUID_FOUND=1
    fi
fi

if [ "$SUID_FOUND" -eq 1 ]; then
    record_poc no_suid_on_interpreters 0 "SUID interpreters found: $SUID_DETAIL"
else
    record_poc no_suid_on_interpreters 1
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

if id testuser >/dev/null 2>&1; then
    record_poc privesc_probe_account_present 1
    PROBE_USER_OK=1
else
    record_poc privesc_probe_account_present 0 "testuser is missing -- cannot run the privilege-escalation probe"
    PROBE_USER_OK=0
fi

if [ "$PROBE_USER_OK" -eq 1 ]; then
    # --- python3: effective UID + kernel-enforced setuid(0) + /etc/shadow read ---
    if command -v python3 >/dev/null 2>&1; then
        PY_EUID=$(su -s /bin/bash -c "python3 -c 'import os; print(os.geteuid())'" testuser 2>/dev/null | tr -d ' \r' || true)
        if [ "$PY_EUID" = "0" ]; then
            record_poc python3_euid_not_root 0 "python3 runs with euid=0 for testuser -- SUID privilege escalation works"
        else
            record_poc python3_euid_not_root 1
        fi

        PY_SETUID=$(su -s /bin/bash -c "python3 -c 'import os
try:
    os.setuid(0)
    print(\"SETUID_ROOT_OK\")
except Exception:
    print(\"SETUID_DENIED\")'" testuser 2>/dev/null | tr -d ' \r' || true)
        if [ "$PY_SETUID" = "SETUID_ROOT_OK" ]; then
            record_poc python3_setuid0_denied 0 "testuser successfully called setuid(0) via python3 -- full root"
        else
            record_poc python3_setuid0_denied 1
        fi

        PY_SHADOW=$(su -s /bin/bash -c "python3 -c '
try:
    open(\"/etc/shadow\").readline()
    print(\"SHADOW_READ_OK\")
except Exception:
    print(\"SHADOW_DENIED\")'" testuser 2>/dev/null | tr -d ' \r' || true)
        if [ "$PY_SHADOW" = "SHADOW_READ_OK" ]; then
            record_poc python3_shadow_read_denied 0 "testuser read /etc/shadow through python3 -- password hashes exposed"
        else
            record_poc python3_shadow_read_denied 1
        fi
    fi

    # --- perl: $> is the effective UID ---
    if command -v perl >/dev/null 2>&1; then
        PL_EUID=$(su -s /bin/bash -c 'perl -e "print \$>"' testuser 2>/dev/null | tr -d ' \r' || true)
        if [ "$PL_EUID" = "0" ]; then
            record_poc perl_euid_not_root 0 "perl runs with euid=0 for testuser -- SUID privilege escalation works"
        else
            record_poc perl_euid_not_root 1
        fi

        PL_SHADOW=$(su -s /bin/bash -c 'perl -e "if (open(F, q{/etc/shadow})) { print q{SHADOW_READ_OK} } else { print q{SHADOW_DENIED} }"' testuser 2>/dev/null | tr -d ' \r' || true)
        if [ "$PL_SHADOW" = "SHADOW_READ_OK" ]; then
            record_poc perl_shadow_read_denied 0 "testuser read /etc/shadow through perl -- password hashes exposed"
        else
            record_poc perl_shadow_read_denied 1
        fi
    fi
fi

# --- Sweep every other SUID interpreter that could grant the same thing ---
OTHER_SUID=""
for cand in /usr/bin/awk /usr/bin/gawk /usr/bin/mawk /usr/bin/ruby* /usr/bin/php* /usr/bin/perl*; do
    [ -f "$cand" ] || continue
    if find "$cand" -perm -4000 2>/dev/null | grep -q .; then
        echo "  [PoC] SUID interpreter left behind: $cand (mode: $(stat -c '%a' "$cand"))"
        OTHER_SUID="${OTHER_SUID}${OTHER_SUID:+, }$cand"
    fi
done
if [ -n "$OTHER_SUID" ]; then
    record_poc no_other_suid_interpreters 0 "SUID interpreters left behind: $OTHER_SUID"
else
    record_poc no_other_suid_interpreters 1
fi

# --- Regression Test: Ensure interpreters still work for normal users ---
echo ""
echo "[Regression] Checking that python3 and perl still work normally..."

# Test python3 execution
PYTHON_BIN=$(command -v python3 2>/dev/null || true)
if [ -z "$PYTHON_BIN" ]; then
    record_reg python3_usable_by_normal_user 0 "python3 binary not found -- interpreter removed or broken"
else
    PYTHON_OUTPUT=$(su -s /bin/bash -c "python3 -c \"print('hello_python')\"" testuser 2>&1) || true
    if [ "$PYTHON_OUTPUT" = "hello_python" ]; then
        record_reg python3_usable_by_normal_user 1
    else
        record_reg python3_usable_by_normal_user 0 "python3 did not produce expected output. Got: $PYTHON_OUTPUT"
    fi
fi

# Test perl execution
PERL_BIN=$(command -v perl 2>/dev/null || true)
if [ -z "$PERL_BIN" ]; then
    record_reg perl_usable_by_normal_user 0 "perl binary not found -- interpreter removed or broken"
else
    PERL_OUTPUT=$(su -s /bin/bash -c "perl -e 'print \"hello_perl\n\"'" testuser 2>&1) || true
    if [ "$PERL_OUTPUT" = "hello_perl" ]; then
        record_reg perl_usable_by_normal_user 1
    else
        record_reg perl_usable_by_normal_user 0 "perl did not produce expected output. Got: $PERL_OUTPUT"
    fi
fi

verify_finish
