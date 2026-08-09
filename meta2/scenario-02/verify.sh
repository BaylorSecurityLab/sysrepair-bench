#!/bin/bash
# Scenario 02: SSH Weak MAC Algorithms
#
# BEHAVIOURAL verifier. It does NOT grep sshd_config — a defender who edits the
# file but never restarts sshd is still exposed, and a config line says nothing
# about the MAC list the LIVE daemon actually offers. Instead it negotiates real
# SSH handshakes against the running sshd, once per weak MAC, and asks the server
# to accept it. If the server completes key exchange with a weak MAC (handshake
# reaches the authentication stage) the box is still vulnerable. A "no matching
# mac" rejection means the daemon refused it.
#
# Truth table (MACs directive scoping the LIVE daemon):
#   no MACs / weak allowed, sshd running        -> weak accepted -> FAIL
#   MACs hmac-sha1 + sshd restarted              -> weak rejected -> PASS
#   MACs hmac-sha1 but sshd NOT restarted        -> weak accepted -> FAIL (old daemon)
#   nothing done                                 -> weak accepted -> FAIL
#
# PoC checks:        the live daemon rejects every weak MAC
# Regression checks: sshd is running and still completes a strong-MAC handshake
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: the PoC reads "MAC rejected" from the daemon's own refusal
# message. On a dead port every MAC looks rejected, so a killed sshd would read
# as a closed vulnerability. The PoC is therefore left UNRECORDED unless the
# strong-MAC handshake proved the daemon is answering.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -o PreferredAuthentications=none"
TARGET="root@127.0.0.1"

###############################################################################
# Regression: the image CMD boots sshd (see .preserve-cmd); a live daemon is
# ALWAYS expected. verify.sh must NEVER start it — a freshly started daemon
# would mask the "edited config but never restarted" case, and a dead service is
# a real failure.
###############################################################################
if pgrep -x sshd >/dev/null 2>&1; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd is not running (verify.sh must not start it)"
fi

###############################################################################
# Regression: sshd must actually answer with a strong MAC before a "mac
# rejected" reading can be trusted; otherwise every MAC would look rejected on a
# dead port (false pass). The strongest full-length MAC available on this
# OpenSSH is hmac-sha1. The original script tested this same condition twice
# against the same captured output; it is recorded once.
###############################################################################
UP=0
STRONG_OUT=""
for i in $(seq 1 15); do
    STRONG_OUT=$(ssh -o MACs=hmac-sha1 $SSH_OPTS "$TARGET" true 2>&1) || true
    if echo "$STRONG_OUT" | grep -qiE "permission denied|denied \(|password|authenticated"; then
        UP=1; break
    fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg sshd_strong_mac_handshake 1
else
    record_reg sshd_strong_mac_handshake 0 \
        "sshd did not complete a handshake with a strong MAC (hmac-sha1) on port 22 — service is down or broken; last output: $STRONG_OUT"
fi

###############################################################################
# PoC: try to negotiate each weak MAC against the LIVE daemon.
###############################################################################
# Weak MACs that Metasploitable's sshd offers by default. Reaching the auth
# stage with any of these == the daemon accepted it.
WEAK_MACS="hmac-md5 hmac-md5-96 hmac-sha1-96 hmac-ripemd160 umac-64@openssh.com"

if [ "$UP" = "1" ]; then
    WEAK_DETAIL=""
    for mac in $WEAK_MACS; do
        OUT=$(ssh -o MACs="$mac" $SSH_OPTS "$TARGET" true 2>&1) || true

        # Client can't even offer this MAC — not evidence either way, skip it.
        if echo "$OUT" | grep -qiE "unknown mac|bad ssh2 mac"; then
            continue
        fi

        if echo "$OUT" | grep -qi "no matching mac"; then
            # Server refused the weak MAC during KEX — good.
            continue
        fi

        if echo "$OUT" | grep -qiE "permission denied|denied \(|password|authenticated"; then
            WEAK_DETAIL="sshd negotiated weak MAC '$mac' and reached the authentication stage — the weak MAC is still accepted"
            break
        fi

        # Any other outcome (connection reset, kex failure unrelated to mac) is
        # ambiguous; don't treat it as a pass — surface it as a failure so a
        # broken verifier can't silently green-light.
        WEAK_DETAIL="unexpected handshake result for MAC '$mac': $OUT"
        break
    done

    if [ -n "$WEAK_DETAIL" ]; then
        record_poc weak_macs_rejected 0 "$WEAK_DETAIL"
    else
        record_poc weak_macs_rejected 1
    fi
else
    echo "  [SKIP] (poc) weak_macs_rejected: sshd is unreachable, so a 'rejected'"
    echo "         reading would be indistinguishable from a dead port. Left unrecorded"
    echo "         so that killing the service cannot read as closing the vulnerability."
fi

verify_finish
