#!/bin/bash
# Verification script for Scenario 02: SSH Weak Host Key Algorithms (ssh-dss/DSA)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
#
# NOTE on platform: on OpenSSH 6.6.1 (Ubuntu 14.04) `HostKeyAlgorithms` is a
# CLIENT-side option only; it is NOT a valid sshd_config directive (added in
# 7.0). The genuine, exploitable weakness is therefore that a DSA host key is
# present and offered. This verifier proves that DYNAMICALLY: it forces a client
# to accept only ssh-dss and checks whether sshd can still complete host-key
# negotiation with it. The verifier never starts sshd -- a dead daemon is FAIL.

PASS=true
HOST=127.0.0.1
PORT=22
SSHOPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 -o PreferredAuthentications=publickey -p $PORT"

if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "FAIL [Regression]: sshd is not running (a fix must restart it, not leave it down)." >&2
    PASS=false
fi

port_listening() {
    local hexport; hexport=$(printf '%04X' "$1")
    awk -v p=":$hexport" '$4=="0A"{split($2,a,":"); if(a[2]==substr(p,2)) f=1} END{exit f?0:1}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}
if ! port_listening "$PORT"; then
    echo "FAIL [Regression]: nothing is listening on TCP $PORT." >&2
    PASS=false
fi

# echo NEGOFAIL (no common host key alg / negotiation refused) | REACHED_AUTH | OTHER:<msg>
probe_hostkey() {
    local out
    out=$(timeout 20 ssh $SSHOPTS -o HostKeyAlgorithms="$1" root@"$HOST" true 2>&1 || true)
    if echo "$out" | grep -qiE 'no matching host key|no hostkey alg|Unable to negotiate'; then
        echo NEGOFAIL
    elif echo "$out" | grep -qiE 'Permission denied|Authenticated|Too many authentication'; then
        echo REACHED_AUTH
    else
        echo "OTHER:$(echo "$out" | tail -1)"
    fi
}

# --- PoC (dynamic): sshd must NOT be able to serve an ssh-dss host key ---
r=$(probe_hostkey "ssh-dss")
case "$r" in
    NEGOFAIL)     echo "PASS [PoC]: sshd no longer offers an ssh-dss (DSA) host key." ;;
    REACHED_AUTH) echo "FAIL [PoC]: sshd still completed host-key negotiation using ssh-dss (DSA key active)." >&2; PASS=false ;;
    *)            echo "FAIL [PoC]: could not probe ssh-dss host key ($r)." >&2; PASS=false ;;
esac

# --- PoC (supporting): the DSA key material must be gone from disk ---
if [ -f /etc/ssh/ssh_host_dsa_key ] || [ -f /etc/ssh/ssh_host_dsa_key.pub ]; then
    echo "FAIL [PoC]: DSA host key file still present under /etc/ssh." >&2
    PASS=false
else
    echo "PASS [PoC]: DSA host key files removed from disk."
fi

# --- Regression: a modern host key algorithm must still negotiate ---
ok=false
for alg in ecdsa-sha2-nistp256 ssh-ed25519 ecdsa-sha2-nistp384; do
    if [ "$(probe_hostkey "$alg")" = "REACHED_AUTH" ]; then ok=true; break; fi
done
if $ok; then
    echo "PASS [Regression]: sshd still serves a modern host key ($alg)."
else
    echo "FAIL [Regression]: sshd could not negotiate any modern host key -- service broken." >&2
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
