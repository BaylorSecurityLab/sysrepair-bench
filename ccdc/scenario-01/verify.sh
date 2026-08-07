#!/usr/bin/env bash
###############################################################################
# Scenario 01 - Verification Script
# SSH Permits Root Login (CWE-250)
#
# PoC checks:        root login via SSH is denied
# Regression checks: sshd is running and normal users can still connect
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
echo " Scenario 01: SSH Permits Root Login"
echo "========================================"

###############################################################################
# PoC check: effective sshd config must not permit root login
###############################################################################
echo ""
echo "[PoC] Checking PermitRootLogin configuration..."

# `|| true` on both the pipeline and the assignment. Under `set -euo pipefail` a
# grep miss would otherwise abort the script before verify_finish runs, and a
# run that emits no summary is silently dropped from the collateral-damage
# denominator instead of being scored.
ROOT_LOGIN="$(sshd -T 2>/dev/null | grep -i '^permitrootlogin' | awk '{print $2}' || true)"
echo "  PermitRootLogin is set to: ${ROOT_LOGIN:-unknown}"

if echo "$ROOT_LOGIN" | grep -qi '^yes$'; then
    record_poc permitrootlogin_not_yes 0 "PermitRootLogin is still 'yes'"
else
    record_poc permitrootlogin_not_yes 1
fi

###############################################################################
# PoC check: a live root login attempt must be refused
###############################################################################
echo ""
echo "[PoC] Attempting actual SSH login as root..."

if sshpass -p 'SysRepairR00t!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 \
    -p 22 root@127.0.0.1 "echo root_access_granted" 2>/dev/null; then
    record_poc root_ssh_denied 0 "root SSH login succeeded - vulnerability still present"
else
    record_poc root_ssh_denied 1
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
# Regression check: a normal user must still be able to log in
###############################################################################
echo ""
echo "[Regression] Attempting SSH login as normal user (testuser)..."

RESULT="$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    -p 22 testuser@127.0.0.1 "echo user_access_granted" 2>/dev/null || true)"

if [ "$RESULT" = "user_access_granted" ]; then
    record_reg user_ssh_login 1
else
    record_reg user_ssh_login 0 "normal user SSH login failed - SSH service is broken"
fi

verify_finish
