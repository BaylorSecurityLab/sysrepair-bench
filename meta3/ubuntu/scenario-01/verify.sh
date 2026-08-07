#!/bin/bash
# Verification script for Scenario 01: SSH Weak KEX Algorithms
# Exit 0 = every check passed, Exit 1 = at least one check failed
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
# The verifier never starts sshd: a dead daemon is a regression FAIL.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "closed the weak KEX but killed sshd" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=22
SSHOPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 -o PreferredAuthentications=publickey -p $PORT"

# --- daemon must already be running (booted by the image CMD) ---
if pgrep -x sshd >/dev/null 2>&1; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd is not running (a fix must restart it, not leave it down)"
fi

# port 22 LISTEN? parse /proc/net/tcp{,6} (state 0A = LISTEN); portable, no ss/netstat needed
port_listening() {
    local hexport; hexport=$(printf '%04X' "$1")
    awk -v p=":$hexport" '$4=="0A"{split($2,a,":"); if(a[2]==substr(p,2)) f=1} END{exit f?0:1}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}
if port_listening "$PORT"; then
    record_reg sshd_port_listening 1
else
    record_reg sshd_port_listening 0 "nothing is listening on TCP $PORT"
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
#
# The OTHER: bucket (no negotiation verdict reached at all) keeps the original
# strictness and counts as a PoC failure: "the probe could not answer" is not
# evidence that the weak algorithm is gone, so it must never be credited.
for weak in diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1; do
    id="weak_kex_refused_$(echo "$weak" | tr '.-' '__')"
    r=$(probe_kex "$weak")
    case "$r" in
        NEGOFAIL)     record_poc "$id" 1 ;;
        REACHED_AUTH) record_poc "$id" 0 "sshd still negotiated weak KEX '$weak' (connection reached authentication)" ;;
        *)            record_poc "$id" 0 "could not probe '$weak' ($r)" ;;
    esac
done

# --- PoC: a modern KEX must negotiate ---
#
# Recorded as a PoC, not a regression. On the untouched box sshd's KexAlgorithms
# is pinned to the SHA-1 set -- that pinning IS the vulnerability -- so this
# probe returns NEGOFAIL at baseline and only starts succeeding once the weak
# list is replaced. A check that can only pass after remediation is evidence the
# fix landed, not evidence that nothing was broken; left labelled "regression"
# it would make the untouched box read as damaged and credit a genuine fix with
# repairing damage it never caused.
#
# Anything other than REACHED_AUTH is a failure, exactly as before -- only the
# kind of the record changed, never the condition or its strictness.
r=$(probe_kex "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256")
if [ "$r" = "REACHED_AUTH" ]; then
    record_poc modern_kex_offered 1
else
    record_poc modern_kex_offered 0 "sshd did not negotiate any modern KEX ($r)"
fi

verify_finish
