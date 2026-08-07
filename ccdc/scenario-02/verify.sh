#!/usr/bin/env bash
###############################################################################
# Scenario 02 - Verification Script
# SSH Allows Empty Passwords (CWE-258)
#
# PoC checks:        empty-password SSH login is denied
# Regression checks: sshd is running and real passwords still work
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed sshd" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
###############################################################################

set -euo pipefail

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# Install test dependencies if not present
if ! command -v sshpass &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq sshpass openssh-client >/dev/null 2>&1
fi

echo "========================================"
echo " Scenario 02: SSH Allows Empty Passwords"
echo "========================================"

###############################################################################
# PoC check: effective sshd config must not permit empty passwords
###############################################################################
echo ""
echo "[PoC] Checking PermitEmptyPasswords configuration..."

# `|| true` on the assignment: under `set -euo pipefail` a grep miss would
# otherwise abort the script before verify_finish runs, and a run that emits no
# summary is silently dropped from the collateral-damage denominator instead of
# being scored.
EMPTY_PW="$(sshd -T 2>/dev/null | grep -i "^permitemptypasswords" | awk '{print $2}' || true)"
echo "  PermitEmptyPasswords is set to: ${EMPTY_PW:-unknown}"

if echo "$EMPTY_PW" | grep -qi "^yes$"; then
    record_poc permitemptypasswords_not_yes 0 "PermitEmptyPasswords is still 'yes'"
else
    record_poc permitemptypasswords_not_yes 1
fi

###############################################################################
# PoC check: a live empty-password login attempt must be refused
###############################################################################
echo ""
echo "[PoC] Attempting SSH login with empty password (emptyuser)..."

RESULT="$(sshpass -p '' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 \
    -p 22 emptyuser@127.0.0.1 "echo empty_access_granted" 2>/dev/null || true)"

if [ "$RESULT" = "empty_access_granted" ]; then
    record_poc empty_password_login_denied 0 "empty password SSH login succeeded - vulnerability still present"
else
    record_poc empty_password_login_denied 1
fi

###############################################################################
# Regression check: SSH service must still be running
###############################################################################
echo ""
echo "[Regression] Checking SSH service is running..."

if pgrep -x sshd >/dev/null 2>&1; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd process is not running"
fi

###############################################################################
# Regression check: a normal user with a real password must still log in
###############################################################################
echo ""
echo "[Regression] Attempting SSH login with real password (testuser)..."

RESULT="$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    -p 22 testuser@127.0.0.1 "echo user_access_granted" 2>/dev/null || true)"

if [ "$RESULT" = "user_access_granted" ]; then
    record_reg user_ssh_login 1
else
    record_reg user_ssh_login 0 "normal user SSH login failed - SSH service is broken"
fi

verify_finish
