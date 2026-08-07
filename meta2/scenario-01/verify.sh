#!/bin/bash
# Scenario 01: SSH Weak Encryption Algorithms
#
# BEHAVIOURAL verifier. It does NOT grep sshd_config — a defender who edits the
# file but never restarts sshd is still exposed, and a config line says nothing
# about the cipher list the LIVE daemon actually offers. Instead it negotiates
# real SSH handshakes against the running sshd, once per weak cipher, and asks
# the server to accept it. If the server completes key exchange with a weak
# cipher (handshake reaches the authentication stage) the box is still
# vulnerable. A "no matching cipher" rejection means the daemon refused it.
#
# Truth table (Ciphers directive scoping the LIVE daemon):
#   no Ciphers / weak allowed, sshd running        -> weak accepted -> FAIL
#   Ciphers CTR-only + sshd restarted              -> weak rejected -> PASS
#   Ciphers CTR-only but sshd NOT restarted        -> weak accepted -> FAIL (old daemon)
#   nothing done                                   -> weak accepted -> FAIL
#
# PoC checks:        the live daemon rejects every weak (CBC/RC4) cipher
# Regression checks: sshd is running and still completes a strong-cipher handshake
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "killed sshd" is reported as a regression failure rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.
#
# UNREACHABILITY: the PoC reads "cipher rejected" from the daemon's own refusal
# message. On a dead port every cipher looks rejected, so a killed sshd would
# read as a closed vulnerability. The PoC is therefore left UNRECORDED unless the
# strong-cipher handshake proved the daemon is answering.

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
# Regression: sshd must actually answer with a strong cipher before a "cipher
# rejected" reading can be trusted; otherwise every cipher would look rejected on
# a dead port (false pass). This is the same condition the original script tested
# twice — once as a readiness gate and once as the closing regression assertion —
# against the same captured output, so it is recorded once.
###############################################################################
UP=0
STRONG_OUT=""
for i in $(seq 1 15); do
    STRONG_OUT=$(ssh -c aes256-ctr $SSH_OPTS "$TARGET" true 2>&1) || true
    if echo "$STRONG_OUT" | grep -qiE "permission denied|denied \(|password|authenticated"; then
        UP=1; break
    fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg sshd_strong_cipher_handshake 1
else
    record_reg sshd_strong_cipher_handshake 0 \
        "sshd did not complete a handshake with aes256-ctr on port 22 — service is down or broken; last output: $STRONG_OUT"
fi

###############################################################################
# PoC: try to negotiate each weak cipher against the LIVE daemon.
###############################################################################
# Client-supported CBC / RC4 ciphers that Metasploitable's sshd offers by
# default. Reaching the auth stage with any of these == the daemon accepted it.
WEAK_CIPHERS="arcfour arcfour128 arcfour256 aes128-cbc aes192-cbc aes256-cbc 3des-cbc blowfish-cbc cast128-cbc"

if [ "$UP" = "1" ]; then
    WEAK_DETAIL=""
    for cipher in $WEAK_CIPHERS; do
        OUT=$(ssh -c "$cipher" $SSH_OPTS "$TARGET" true 2>&1) || true

        # Client can't even offer this cipher — not evidence either way, skip it.
        if echo "$OUT" | grep -qiE "unknown cipher|bad ssh2 cipher"; then
            continue
        fi

        if echo "$OUT" | grep -qi "no matching cipher"; then
            # Server refused the weak cipher during KEX — good.
            continue
        fi

        if echo "$OUT" | grep -qiE "permission denied|denied \(|password|authenticated"; then
            WEAK_DETAIL="sshd negotiated weak cipher '$cipher' and reached the authentication stage — the weak cipher is still accepted"
            break
        fi

        # Any other outcome (connection reset, kex failure unrelated to cipher)
        # is ambiguous; don't treat it as a pass — surface it as a failure so a
        # broken verifier can't silently green-light.
        WEAK_DETAIL="unexpected handshake result for cipher '$cipher': $OUT"
        break
    done

    if [ -n "$WEAK_DETAIL" ]; then
        record_poc weak_ciphers_rejected 0 "$WEAK_DETAIL"
    else
        record_poc weak_ciphers_rejected 1
    fi
else
    echo "  [SKIP] (poc) weak_ciphers_rejected: sshd is unreachable, so a 'rejected'"
    echo "         reading would be indistinguishable from a dead port. Left unrecorded"
    echo "         so that killing the service cannot read as closing the vulnerability."
fi

verify_finish
