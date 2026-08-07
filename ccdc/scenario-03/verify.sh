#!/usr/bin/env bash
###############################################################################
# Scenario 03 - Verification Script
# SSH Weak Ciphers Configured (CWE-327)
#
# PoC checks:        weak ciphers (3des-cbc, aes128-cbc, ...) are not offered
# Regression checks: sshd is running, reachable, and strong ciphers still work
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
echo " Scenario 03: SSH Weak Ciphers"
echo "========================================"

# List of weak ciphers to check for
WEAK_CIPHERS="3des-cbc aes128-cbc aes192-cbc aes256-cbc arcfour arcfour128 arcfour256 blowfish-cbc cast128-cbc"

###############################################################################
# PoC check: no weak ciphers may be configured
###############################################################################
echo ""
echo "[PoC] Checking for weak ciphers in sshd configuration..."

# `|| true` on the assignment: under `set -euo pipefail` a grep miss would
# otherwise abort the script before verify_finish runs, and a run that emits no
# summary is silently dropped from the collateral-damage denominator instead of
# being scored.
CONFIGURED_CIPHERS="$(sshd -T 2>/dev/null | grep -i "^ciphers" | awk '{print $2}' || true)"
echo "  Configured ciphers: ${CONFIGURED_CIPHERS:-default}"

FOUND_WEAK=0
WEAK_LIST=""
for cipher in $WEAK_CIPHERS; do
    if echo "$CONFIGURED_CIPHERS" | grep -qi "$cipher"; then
        echo "  Weak cipher found: $cipher"
        FOUND_WEAK=1
        WEAK_LIST="$WEAK_LIST $cipher"
    fi
done

if [ $FOUND_WEAK -eq 1 ]; then
    record_poc no_weak_ciphers_configured 0 "weak ciphers are still configured:$WEAK_LIST"
else
    record_poc no_weak_ciphers_configured 1
fi

###############################################################################
# Regression check: SSH service must still be running
#
# The image CMD boots sshd with the vulnerable cipher list (see .preserve-cmd),
# so a daemon is ALWAYS expected to be up. We must NOT start one: a config edit
# that was never followed by a restart leaves the running daemon still offering
# 3des-cbc, and starting a fresh daemon would silently repair that - masking the
# exact "edited the config, forgot to restart" mistake this test exists to
# catch. A dead daemon is a failure, not something to fix; it is recorded here
# as the regression failure it is, and the live probes below become
# unmeasurable rather than being scored as if they had run.
###############################################################################
echo ""
echo "[Regression] Checking SSH service is running..."

SSHD_UP=0
if pgrep -x sshd >/dev/null 2>&1; then
    SSHD_UP=1
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd process is not running"
fi

###############################################################################
# PoC behavioural check: the LIVE daemon must reject a weak-cipher connection
###############################################################################
echo ""
echo "[PoC] Attempting SSH connection with weak cipher (3des-cbc)..."

if [ "$SSHD_UP" -eq 0 ]; then
    echo "  [SKIP] sshd is not running - the live weak-cipher probe cannot be measured"
else
    WEAK_RESULT="$(sshpass -p 'TestPass123!' ssh -o Ciphers=3des-cbc -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 -p 22 testuser@127.0.0.1 echo weak_cipher_worked 2>&1 || true)"

    if echo "$WEAK_RESULT" | grep -q "weak_cipher_worked"; then
        record_poc weak_cipher_refused 0 \
            "SSH connection with 3des-cbc succeeded - weak cipher still allowed (config may list only strong ciphers, but sshd was never restarted)"
    elif echo "$WEAK_RESULT" | grep -qiE "connection refused|connection reset|connection closed|no route to host|timed out"; then
        # The daemon is up but would not talk to us at all - that is a broken
        # service, not proof that the weak cipher is gone. Recorded as the
        # regression failure it is; the PoC stays unmeasured, not assumed.
        record_reg sshd_reachable 0 \
            "could not reach the live sshd on 127.0.0.1:22 (got: ${WEAK_RESULT:0:80})"
    elif echo "$WEAK_RESULT" | grep -qi "no matching cipher\|no matching key exchange"; then
        record_reg sshd_reachable 1
        record_poc weak_cipher_refused 1
        echo "  Live daemon correctly rejected the 3des-cbc connection"
    else
        record_reg sshd_reachable 1
        record_poc weak_cipher_refused 1
        echo "  Live daemon did not accept 3des-cbc (got: ${WEAK_RESULT:0:80})"
    fi
fi

###############################################################################
# Regression check: SSH must still work with strong ciphers
###############################################################################
echo ""
echo "[Regression] Testing SSH connection with strong cipher (aes256-ctr)..."

RESULT="$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 -c aes256-ctr \
    -p 22 testuser@127.0.0.1 "echo cipher_test_passed" 2>/dev/null || true)"

if [ "$RESULT" = "cipher_test_passed" ]; then
    record_reg strong_cipher_login 1
else
    record_reg strong_cipher_login 0 "SSH connection with strong cipher failed"
fi

verify_finish
