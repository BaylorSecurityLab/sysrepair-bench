#!/usr/bin/env bash
###############################################################################
# Scenario 04 - Verification Script
# SSH X11 Forwarding + High MaxAuthTries (CWE-307)
#
# PoC Test:        Verify X11Forwarding is off, MaxAuthTries <= 6
# Regression Test: Verify SSH still works normally
#
# Exit 0 = remediation successful (PoC fails AND functionality works)
# Exit 1 = remediation failed
###############################################################################

set -euo pipefail

PASS=0
FAIL=1

# Install test dependencies if not present
if ! command -v sshpass &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq sshpass openssh-client >/dev/null 2>&1
fi

echo "========================================"
echo " Scenario 04: X11 Forwarding + MaxAuthTries"
echo "========================================"

###############################################################################
# PoC Test: Check X11Forwarding
###############################################################################
echo ""
echo "[PoC Test] Checking X11Forwarding configuration..."

X11FWD=$(sshd -T 2>/dev/null | grep -i "^x11forwarding" | awk '{print $2}')
echo "  X11Forwarding is set to: ${X11FWD:-unknown}"

if echo "$X11FWD" | grep -qi "^yes$"; then
    echo "  [FAIL] X11Forwarding is still enabled"
    exit $FAIL
fi

echo "  [PASS] X11Forwarding is disabled"

###############################################################################
# PoC Test: Check MaxAuthTries
###############################################################################
echo ""
echo "[PoC Test] Checking MaxAuthTries configuration..."

MAX_AUTH=$(sshd -T 2>/dev/null | grep -i "^maxauthtries" | awk '{print $2}')
echo "  MaxAuthTries is set to: ${MAX_AUTH:-unknown}"

if [ -z "$MAX_AUTH" ]; then
    echo "  [FAIL] Could not determine MaxAuthTries"
    exit $FAIL
fi

if [ "$MAX_AUTH" -gt 6 ]; then
    echo "  [FAIL] MaxAuthTries is $MAX_AUTH (should be 6 or less)"
    exit $FAIL
fi

echo "  [PASS] MaxAuthTries is $MAX_AUTH (acceptable: <= 6)"

###############################################################################
# PoC Behavioral Test (RUNTIME): X11 forwarding must be refused by the LIVE
# daemon.
#
# NOTE: `sshd -T` above only PARSES /etc/ssh/sshd_config. A config edit without
# a service restart leaves the running daemon fully vulnerable, and that state
# MUST fail. Everything below talks to the daemon on the wire instead.
#
# `ssh -X` is a NO-OP when the client has no $DISPLAY - it never even sends the
# x11-req channel request, so the old version of this test passed trivially.
# Set up a throwaway DISPLAY + MIT-MAGIC-COOKIE-1 so the client genuinely asks
# for X11 forwarding, then read $DISPLAY on the REMOTE side: a non-empty
# "localhost:10.0" proves the server allocated a real X11 forwarding channel.
###############################################################################
echo ""
echo "[PoC Test] Attempting REAL X11 forwarding against the running daemon..."

# The behavioural tests below are mandatory - a dead daemon cannot be shown to
# be remediated.
if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "  [FAIL] sshd is not running - cannot prove X11 forwarding is refused"
    exit $FAIL
fi

X11_XAUTH=/tmp/.x11probe.$$.Xauth
# Snapshot the target user's Xauthority so the probe leaves no trace.
VICTIM_XAUTH=$(getent passwd testuser | cut -d: -f6)/.Xauthority
VICTIM_XAUTH_EXISTED=0
[ -e "$VICTIM_XAUTH" ] && VICTIM_XAUTH_EXISTED=1

: > "$X11_XAUTH"
COOKIE=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
xauth -f "$X11_XAUTH" add :99 MIT-MAGIC-COOKIE-1 "$COOKIE" >/dev/null 2>&1

X11_RESULT=$(DISPLAY=:99 XAUTHORITY="$X11_XAUTH" \
    sshpass -p 'TestPass123!' ssh -Y -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 -p 22 testuser@127.0.0.1 \
    'echo X11_DISPLAY=[$DISPLAY]' 2>&1 || true)

# Restore prior state - verify.sh must not permanently mutate the system.
rm -f "$X11_XAUTH"
if [ "$VICTIM_XAUTH_EXISTED" -eq 0 ]; then
    rm -f "$VICTIM_XAUTH"
fi

REMOTE_DISPLAY=$(echo "$X11_RESULT" | sed -n 's/.*X11_DISPLAY=\[\(.*\)\].*/\1/p' | tail -1)

if ! echo "$X11_RESULT" | grep -q 'X11_DISPLAY='; then
    echo "  [FAIL] Could not run the X11 probe over SSH (got: ${X11_RESULT:0:120})"
    exit $FAIL
fi

if [ -n "$REMOTE_DISPLAY" ]; then
    echo "  [FAIL] Live daemon GRANTED X11 forwarding - remote DISPLAY=$REMOTE_DISPLAY"
    echo "         (config may say X11Forwarding no, but sshd was never restarted)"
    exit $FAIL
fi

echo "  [PASS] Live daemon refused X11 forwarding (remote DISPLAY is empty)"

###############################################################################
# PoC Behavioral Test (RUNTIME): MaxAuthTries must be enforced on the wire.
#
# sshd counts every failed public-key offer against MaxAuthTries and then drops
# the connection. Offer 8 throwaway keys and count how many the RUNNING server
# actually accepted before cutting us off. Vulnerable (MaxAuthTries 30) -> all 8
# get offered. Remediated (<= 6) -> the server disconnects early.
###############################################################################
echo ""
echo "[PoC Test] Probing enforced MaxAuthTries on the running daemon..."

PROBE_KEYS=/tmp/.maxauth_probe.$$
rm -rf "$PROBE_KEYS"; mkdir -p "$PROBE_KEYS"
IDOPTS=""
for i in 1 2 3 4 5 6 7 8; do
    ssh-keygen -q -t ed25519 -N '' -f "$PROBE_KEYS/k$i" >/dev/null 2>&1
    IDOPTS="$IDOPTS -i $PROBE_KEYS/k$i"
done

# shellcheck disable=SC2086
AUTH_OUT=$(ssh -v $IDOPTS -o IdentitiesOnly=yes \
    -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes \
    -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes \
    -p 22 testuser@127.0.0.1 true 2>&1 || true)

rm -rf "$PROBE_KEYS"

OFFERS=$(echo "$AUTH_OUT" | grep -c "Offering public key" || true)
echo "  Server accepted $OFFERS public-key attempts before disconnecting"

if [ "$OFFERS" -gt 6 ]; then
    echo "  [FAIL] Running daemon allowed $OFFERS auth attempts (MaxAuthTries > 6)"
    echo "         (config may say MaxAuthTries 4, but sshd was never restarted)"
    exit $FAIL
fi

echo "  [PASS] Running daemon enforces MaxAuthTries <= 6"

###############################################################################
# Regression Test: SSH service must still be running
###############################################################################
echo ""
echo "[Regression Test] Checking SSH service is running..."

if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "  [FAIL] sshd process is not running"
    exit $FAIL
fi
echo "  [PASS] sshd process is running"

###############################################################################
# Regression Test: SSH connection must still work
###############################################################################
echo ""
echo "[Regression Test] Attempting SSH login as testuser..."

RESULT=$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    -p 22 testuser@127.0.0.1 "echo user_access_granted" 2>/dev/null || true)

if [ "$RESULT" != "user_access_granted" ]; then
    echo "  [FAIL] SSH login failed - service is broken"
    exit $FAIL
fi
echo "  [PASS] SSH login works correctly"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
