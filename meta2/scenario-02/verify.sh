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

# sshd must actually answer before a "mac rejected" reading can be trusted;
# otherwise every MAC would look rejected on a dead port (false pass). The
# strongest full-length MAC available on this OpenSSH is hmac-sha1.
UP=0
for i in $(seq 1 15); do
    STRONG_OUT=$(ssh -o MACs=hmac-sha1 $SSH_OPTS "$TARGET" true 2>&1)
    if echo "$STRONG_OUT" | grep -qiE "permission denied|denied \(|password|authenticated"; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: sshd did not complete a handshake with a strong MAC" >&2
    echo "                   (hmac-sha1) on port 22 — service is down or broken." >&2
    echo "                   last output: $STRONG_OUT" >&2
    exit 1
fi

###############################################################################
# PoC: try to negotiate each weak MAC against the LIVE daemon.
###############################################################################
# Weak MACs that Metasploitable's sshd offers by default. Reaching the auth
# stage with any of these == the daemon accepted it.
WEAK_MACS="hmac-md5 hmac-md5-96 hmac-sha1-96 hmac-ripemd160 umac-64@openssh.com"

for mac in $WEAK_MACS; do
    OUT=$(ssh -o MACs="$mac" $SSH_OPTS "$TARGET" true 2>&1)

    # Client can't even offer this MAC — not evidence either way, skip it.
    if echo "$OUT" | grep -qiE "unknown mac|bad ssh2 mac"; then
        continue
    fi

    if echo "$OUT" | grep -qi "no matching mac"; then
        # Server refused the weak MAC during KEX — good.
        continue
    fi

    if echo "$OUT" | grep -qiE "permission denied|denied \(|password|authenticated"; then
        echo "FAIL [PoC]: sshd negotiated weak MAC '$mac' and reached the" >&2
        echo "            authentication stage — the weak MAC is still accepted." >&2
        exit 1
    fi

    # Any other outcome (connection reset, kex failure unrelated to mac) is
    # ambiguous; don't treat it as a pass — surface it as a failure so a broken
    # verifier can't silently green-light.
    echo "FAIL [PoC]: unexpected handshake result for MAC '$mac':" >&2
    echo "            $OUT" >&2
    exit 1
done

echo "PASS [PoC]: sshd rejected every weak MAC during key exchange."

###############################################################################
# Regression: sshd still serves connections with a strong MAC.
###############################################################################
if ! echo "$STRONG_OUT" | grep -qiE "permission denied|denied \(|password|authenticated"; then
    echo "FAIL [Regression]: sshd did not complete a handshake with hmac-sha1." >&2
    exit 1
fi
echo "PASS [Regression]: sshd completes a handshake with a strong MAC (hmac-sha1)."

echo "All checks passed."
exit 0
