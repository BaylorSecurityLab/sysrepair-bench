#!/bin/bash
# Verification script for Scenario 02: SSH Weak Host Key Algorithms (ssh-dss/DSA)
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# NOTE on platform: on OpenSSH 6.6.1 (Ubuntu 14.04) `HostKeyAlgorithms` is a
# CLIENT-side option only; it is NOT a valid sshd_config directive (added in
# 7.0). The genuine, exploitable weakness is therefore that a DSA host key is
# present and offered. This verifier proves that DYNAMICALLY: it forces a client
# to accept only ssh-dss and checks whether sshd can still complete host-key
# negotiation with it. The verifier never starts sshd -- a dead daemon is a
# regression FAIL.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "removed the DSA key but killed sshd" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=22
SSHOPTS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 -o PreferredAuthentications=publickey -p $PORT"

if pgrep -x sshd >/dev/null 2>&1; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd is not running (a fix must restart it, not leave it down)"
fi

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
#
# OTHER: means the probe never reached a negotiation verdict -- sshd unreachable.
# That is service damage, not a closed vulnerability, so it is recorded as a
# regression failure and the PoC is left unrecorded.
r=$(probe_hostkey "ssh-dss")
case "$r" in
    NEGOFAIL)     record_poc ssh_dss_hostkey_refused 1 ;;
    REACHED_AUTH) record_poc ssh_dss_hostkey_refused 0 "sshd still completed host-key negotiation using ssh-dss (DSA key active)" ;;
    *)            record_reg sshd_reachable 0 "could not probe ssh-dss host key ($r) -- sshd unreachable" ;;
esac

# --- PoC (supporting): the DSA key material must be gone from disk ---
if [ -f /etc/ssh/ssh_host_dsa_key ] || [ -f /etc/ssh/ssh_host_dsa_key.pub ]; then
    record_poc dsa_hostkey_files_removed 0 "DSA host key file still present under /etc/ssh"
else
    record_poc dsa_hostkey_files_removed 1
fi

# --- Regression: a modern host key algorithm must still negotiate ---
ok=false
for alg in ecdsa-sha2-nistp256 ssh-ed25519 ecdsa-sha2-nistp384; do
    if [ "$(probe_hostkey "$alg")" = "REACHED_AUTH" ]; then ok=true; break; fi
done
if $ok; then
    record_reg modern_hostkey_negotiates 1
else
    record_reg modern_hostkey_negotiates 0 "sshd could not negotiate any modern host key -- service broken"
fi

verify_finish
