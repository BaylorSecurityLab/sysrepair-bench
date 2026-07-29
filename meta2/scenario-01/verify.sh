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
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -o PreferredAuthentications=none"
TARGET="root@127.0.0.1"

###############################################################################
# The image CMD boots sshd (see .preserve-cmd); a live daemon is ALWAYS
# expected. verify.sh must NEVER start it — a freshly started daemon would mask
# the "edited config but never restarted" case, and a dead service is a real
# failure.
###############################################################################
if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "FAIL [Regression]: sshd is not running — a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# sshd must actually answer before a "cipher rejected" reading can be trusted;
# otherwise every cipher would look rejected on a dead port (false pass).
UP=0
for i in $(seq 1 15); do
    STRONG_OUT=$(ssh -c aes256-ctr $SSH_OPTS "$TARGET" true 2>&1)
    if echo "$STRONG_OUT" | grep -qiE "permission denied|denied \(|password|authenticated"; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: sshd did not complete a handshake with a strong (CTR)" >&2
    echo "                   cipher on port 22 — service is down or broken." >&2
    echo "                   last output: $STRONG_OUT" >&2
    exit 1
fi

###############################################################################
# PoC: try to negotiate each weak cipher against the LIVE daemon.
###############################################################################
# Client-supported CBC / RC4 ciphers that Metasploitable's sshd offers by
# default. Reaching the auth stage with any of these == the daemon accepted it.
WEAK_CIPHERS="arcfour arcfour128 arcfour256 aes128-cbc aes192-cbc aes256-cbc 3des-cbc blowfish-cbc cast128-cbc"

for cipher in $WEAK_CIPHERS; do
    OUT=$(ssh -c "$cipher" $SSH_OPTS "$TARGET" true 2>&1)

    # Client can't even offer this cipher — not evidence either way, skip it.
    if echo "$OUT" | grep -qiE "unknown cipher|bad ssh2 cipher"; then
        continue
    fi

    if echo "$OUT" | grep -qi "no matching cipher"; then
        # Server refused the weak cipher during KEX — good.
        continue
    fi

    if echo "$OUT" | grep -qiE "permission denied|denied \(|password|authenticated"; then
        echo "FAIL [PoC]: sshd negotiated weak cipher '$cipher' and reached the" >&2
        echo "            authentication stage — the weak cipher is still accepted." >&2
        exit 1
    fi

    # Any other outcome (connection reset, kex failure unrelated to cipher) is
    # ambiguous; don't treat it as a pass — surface it as a failure so a broken
    # verifier can't silently green-light.
    echo "FAIL [PoC]: unexpected handshake result for cipher '$cipher':" >&2
    echo "            $OUT" >&2
    exit 1
done

echo "PASS [PoC]: sshd rejected every weak (CBC/RC4) cipher during key exchange."

###############################################################################
# Regression: sshd still serves connections with a strong cipher.
###############################################################################
if ! echo "$STRONG_OUT" | grep -qiE "permission denied|denied \(|password|authenticated"; then
    echo "FAIL [Regression]: sshd did not complete a handshake with aes256-ctr." >&2
    exit 1
fi
echo "PASS [Regression]: sshd completes a handshake with a strong (CTR) cipher."

echo "All checks passed."
exit 0
