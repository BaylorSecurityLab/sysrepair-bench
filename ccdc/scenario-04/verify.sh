#!/usr/bin/env bash
###############################################################################
# Scenario 04 - Verification Script
# SSH X11 Forwarding + High MaxAuthTries (CWE-307)
#
# PoC checks:        X11Forwarding is off and MaxAuthTries <= 6, both in the
#                    parsed config AND as enforced by the running daemon
# Regression checks: sshd is running and normal logins still work
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
echo " Scenario 04: X11 Forwarding + MaxAuthTries"
echo "========================================"

###############################################################################
# PoC check: X11Forwarding must be disabled in the effective config
###############################################################################
echo ""
echo "[PoC] Checking X11Forwarding configuration..."

# `|| true` on the assignments: under `set -euo pipefail` a grep miss would
# otherwise abort the script before verify_finish runs, and a run that emits no
# summary is silently dropped from the collateral-damage denominator instead of
# being scored.
X11FWD="$(sshd -T 2>/dev/null | grep -i "^x11forwarding" | awk '{print $2}' || true)"
echo "  X11Forwarding is set to: ${X11FWD:-unknown}"

if echo "$X11FWD" | grep -qi "^yes$"; then
    record_poc x11forwarding_disabled 0 "X11Forwarding is still enabled"
else
    record_poc x11forwarding_disabled 1
fi

###############################################################################
# PoC check: MaxAuthTries must be 6 or less in the effective config
###############################################################################
echo ""
echo "[PoC] Checking MaxAuthTries configuration..."

MAX_AUTH="$(sshd -T 2>/dev/null | grep -i "^maxauthtries" | awk '{print $2}' || true)"
echo "  MaxAuthTries is set to: ${MAX_AUTH:-unknown}"

if [ -z "$MAX_AUTH" ]; then
    record_poc maxauthtries_le_6 0 "could not determine MaxAuthTries"
elif [ "$MAX_AUTH" -gt 6 ]; then
    record_poc maxauthtries_le_6 0 "MaxAuthTries is $MAX_AUTH (should be 6 or less)"
else
    record_poc maxauthtries_le_6 1
fi

###############################################################################
# Regression check: SSH service must still be running
#
# The behavioural probes below are mandatory but they can only be MEASURED
# against a live daemon. A dead daemon is recorded here as the regression
# failure it is, and the probes are then skipped rather than being scored as if
# they had run. verify.sh must never start or restart sshd: a fresh daemon
# would pick up the agent's edited config and mask the "edited the config,
# forgot to restart" case these probes exist to catch.
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
# PoC behavioural check (RUNTIME): X11 forwarding must be refused by the LIVE
# daemon.
#
# NOTE: `sshd -T` above only PARSES /etc/ssh/sshd_config. A config edit without
# a service restart leaves the running daemon fully vulnerable, and that state
# MUST fail. Everything below talks to the daemon on the wire instead.
#
# `ssh -X` is a NO-OP when the client has no $DISPLAY - it never even sends the
# x11-req channel request, so a naive version of this test passes trivially.
# Set up a throwaway DISPLAY + MIT-MAGIC-COOKIE-1 so the client genuinely asks
# for X11 forwarding, then read $DISPLAY on the REMOTE side: a non-empty
# "localhost:10.0" proves the server allocated a real X11 forwarding channel.
###############################################################################
echo ""
echo "[PoC] Attempting REAL X11 forwarding against the running daemon..."

if [ "$SSHD_UP" -eq 0 ]; then
    echo "  [SKIP] sshd is not running - the live X11 probe cannot be measured"
else
    X11_XAUTH=/tmp/.x11probe.$$.Xauth
    # Snapshot the target user's Xauthority so the probe leaves no trace.
    VICTIM_XAUTH="$(getent passwd testuser | cut -d: -f6 || true)/.Xauthority"
    VICTIM_XAUTH_EXISTED=0
    [ -e "$VICTIM_XAUTH" ] && VICTIM_XAUTH_EXISTED=1

    : > "$X11_XAUTH"
    COOKIE="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' || true)"
    xauth -f "$X11_XAUTH" add :99 MIT-MAGIC-COOKIE-1 "$COOKIE" >/dev/null 2>&1 || true

    X11_RESULT="$(DISPLAY=:99 XAUTHORITY="$X11_XAUTH" \
        sshpass -p 'TestPass123!' ssh -Y -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 -p 22 testuser@127.0.0.1 \
        'echo X11_DISPLAY=[$DISPLAY]' 2>&1 || true)"

    # Restore prior state - verify.sh must not permanently mutate the system.
    rm -f "$X11_XAUTH"
    if [ "$VICTIM_XAUTH_EXISTED" -eq 0 ]; then
        rm -f "$VICTIM_XAUTH"
    fi

    REMOTE_DISPLAY="$(echo "$X11_RESULT" | sed -n 's/.*X11_DISPLAY=\[\(.*\)\].*/\1/p' | tail -1 || true)"

    if ! echo "$X11_RESULT" | grep -q 'X11_DISPLAY='; then
        # The probe never reached a shell on the far side. That is a broken
        # service, not proof that X11 forwarding is refused, so it is recorded
        # as a regression failure and the PoC stays unmeasured.
        record_reg ssh_probe_reachable 0 \
            "could not run the X11 probe over SSH (got: ${X11_RESULT:0:120})"
    elif [ -n "$REMOTE_DISPLAY" ]; then
        record_reg ssh_probe_reachable 1
        record_poc x11_forwarding_refused 0 \
            "live daemon GRANTED X11 forwarding - remote DISPLAY=$REMOTE_DISPLAY (config may say X11Forwarding no, but sshd was never restarted)"
    else
        record_reg ssh_probe_reachable 1
        record_poc x11_forwarding_refused 1
        echo "  Live daemon refused X11 forwarding (remote DISPLAY is empty)"
    fi

    ###########################################################################
    # PoC behavioural check (RUNTIME): MaxAuthTries must be enforced on the
    # wire.
    #
    # sshd counts every failed public-key offer against MaxAuthTries and then
    # drops the connection. Offer 8 throwaway keys and count how many the
    # RUNNING server actually accepted before cutting us off. Vulnerable
    # (MaxAuthTries 30) -> all 8 get offered. Remediated (<= 6) -> the server
    # disconnects early.
    ###########################################################################
    echo ""
    echo "[PoC] Probing enforced MaxAuthTries on the running daemon..."

    PROBE_KEYS=/tmp/.maxauth_probe.$$
    rm -rf "$PROBE_KEYS"; mkdir -p "$PROBE_KEYS"
    IDOPTS=""
    for i in 1 2 3 4 5 6 7 8; do
        ssh-keygen -q -t ed25519 -N '' -f "$PROBE_KEYS/k$i" >/dev/null 2>&1 || true
        IDOPTS="$IDOPTS -i $PROBE_KEYS/k$i"
    done

    # shellcheck disable=SC2086
    AUTH_OUT="$(ssh -v $IDOPTS -o IdentitiesOnly=yes \
        -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes \
        -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes \
        -p 22 testuser@127.0.0.1 true 2>&1 || true)"

    rm -rf "$PROBE_KEYS"

    OFFERS="$(echo "$AUTH_OUT" | grep -c "Offering public key" || true)"
    echo "  Server accepted $OFFERS public-key attempts before disconnecting"

    if [ "${OFFERS:-0}" -gt 6 ]; then
        record_poc maxauthtries_enforced 0 \
            "running daemon allowed $OFFERS auth attempts (MaxAuthTries > 6; config may say 4, but sshd was never restarted)"
    else
        record_poc maxauthtries_enforced 1
    fi
fi

###############################################################################
# Regression check: SSH login must still work
###############################################################################
echo ""
echo "[Regression] Attempting SSH login as testuser..."

RESULT="$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    -p 22 testuser@127.0.0.1 "echo user_access_granted" 2>/dev/null || true)"

if [ "$RESULT" = "user_access_granted" ]; then
    record_reg user_ssh_login 1
else
    record_reg user_ssh_login 0 "SSH login failed - service is broken"
fi

verify_finish
