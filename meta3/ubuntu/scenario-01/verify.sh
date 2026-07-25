#!/bin/bash
# Verification script for Scenario 01: SSH Weak KEX Algorithms
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
#
# This is a LIVE check against the running sshd. It does NOT parse sshd_config
# (parsing is not runtime evidence and cannot tell a restarted daemon from an
# edited-but-not-restarted one). Instead it forces specific key-exchange
# methods over a real TCP connection and reads sshd's negotiation result.
#
# Key subtlety: with BatchMode and no key, EVERY connection ends non-zero, so
# the ssh exit code cannot distinguish "KEX accepted" from "KEX refused". We
# classify on stderr instead:
#   * "Unable to negotiate a key exchange method"  -> KEX refused  (good)
#   * "Permission denied" / reached authentication -> KEX accepted (bad here)
# The verifier never starts sshd: a dead daemon is a FAIL.

PASS=true
HOST=127.0.0.1
PORT=22
SSHOPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 -o PreferredAuthentications=publickey -p $PORT"

# --- daemon must already be running (booted by the image CMD) ---
if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "FAIL [Regression]: sshd is not running (a fix must restart it, not leave it down)." >&2
    PASS=false
fi

# port 22 LISTEN? parse /proc/net/tcp{,6} (state 0A = LISTEN); portable, no ss/netstat needed
port_listening() {
    local hexport; hexport=$(printf '%04X' "$1")
    awk -v p=":$hexport" '$4=="0A"{split($2,a,":"); if(a[2]==substr(p,2)) f=1} END{exit f?0:1}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}
if ! port_listening "$PORT"; then
    echo "FAIL [Regression]: nothing is listening on TCP $PORT." >&2
    PASS=false
fi

# echo one of: NEGOFAIL | REACHED_AUTH | OTHER:<last line>
probe_kex() {
    local out
    out=$(timeout 20 ssh $SSHOPTS -o KexAlgorithms="$1" root@"$HOST" true 2>&1 || true)
    if echo "$out" | grep -qi 'Unable to negotiate'; then
        echo NEGOFAIL
    elif echo "$out" | grep -qiE 'Permission denied|Authenticated|Too many authentication'; then
        echo REACHED_AUTH
    else
        echo "OTHER:$(echo "$out" | tail -1)"
    fi
}

# --- PoC: each weak SHA1 KEX must be REFUSED at negotiation ---
for weak in diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1; do
    r=$(probe_kex "$weak")
    case "$r" in
        NEGOFAIL)     echo "PASS [PoC]: sshd refused weak KEX '$weak'." ;;
        REACHED_AUTH) echo "FAIL [PoC]: sshd still negotiated weak KEX '$weak' (connection reached authentication)." >&2; PASS=false ;;
        *)            echo "FAIL [PoC]: could not probe '$weak' ($r)." >&2; PASS=false ;;
    esac
done

# --- Regression: a modern KEX must still negotiate (service usable) ---
r=$(probe_kex "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256")
if [ "$r" = "REACHED_AUTH" ]; then
    echo "PASS [Regression]: sshd still negotiates a modern KEX."
else
    echo "FAIL [Regression]: sshd did not negotiate any modern KEX ($r) -- service broken." >&2
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
