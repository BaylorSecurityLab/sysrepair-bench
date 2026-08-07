#!/bin/bash
# Scenario 03: SSH Default Credentials
#
# BEHAVIOURAL verifier. It does NOT grep sshd_config and does NOT crack
# /etc/shadow offline — it drives REAL SSH logins against the running daemon
# with the known Metasploitable default credentials. If any of them yields a
# shell, the box is still vulnerable. A defender who edits sshd_config
# (PasswordAuthentication no) but never restarts sshd is still exposed, and the
# live login will prove it.
#
# Passwords are fed non-interactively via SSH_ASKPASS (sshpass is not present on
# this 2008-era image); `setsid` + </dev/null detaches the tty so ssh consults
# the askpass helper.
#
# PoC checks:        no default credential (root/msfadmin/user) yields a shell
# Regression checks: sshd is running and still completes a handshake to auth
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: a dead port rejects every credential, so a killed sshd would
# read as "default credentials no longer work". The PoC is therefore left
# UNRECORDED unless the handshake probe proved the daemon is answering.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1"
DEFAULT_CREDS="root:root msfadmin:msfadmin user:user"

# askpass helper: prints the password we stash in $ASKPASS_VALUE
AP=/tmp/.s03_askpass
cat > "$AP" <<'EOF'
#!/bin/sh
echo "$ASKPASS_VALUE"
EOF
chmod +x "$AP"
cleanup() { rm -f "$AP"; }
trap cleanup EXIT

# Try a password login. Echoes "LOGIN_OK" on success. Password auth forced,
# pubkey disabled, so we test exactly the credential path.
try_login() {
    local user="$1" pass="$2"
    DISPLAY=:0 SSH_ASKPASS="$AP" ASKPASS_VALUE="$pass" setsid \
        ssh $SSH_OPTS -o PreferredAuthentications=password,keyboard-interactive \
            -o PubkeyAuthentication=no "$user"@127.0.0.1 'echo LOGIN_OK' \
        </dev/null 2>&1
}

###############################################################################
# Regression: a live daemon is ALWAYS expected (see .preserve-cmd). verify.sh
# must NEVER start it — a freshly started daemon would mask the "edited config
# but never restarted" case, and a dead service is a real failure.
###############################################################################
if pgrep -x sshd >/dev/null 2>&1; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd is not running (verify.sh must not start it)"
fi

###############################################################################
# Regression: sshd must complete a handshake to the auth stage before a "login
# rejected" reading can be trusted; otherwise a slow or dead port would read as
# a remediated box. The original script tested this same PROBE output twice —
# once as a readiness gate and once as the closing regression assertion — so it
# is recorded once.
###############################################################################
UP=0
PROBE=""
for i in $(seq 1 15); do
    PROBE=$(ssh $SSH_OPTS -o BatchMode=yes -o PreferredAuthentications=none root@127.0.0.1 true 2>&1) || true
    if echo "$PROBE" | grep -qiE "permission denied|denied \(|password|publickey|authenticated"; then
        UP=1; break
    fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg sshd_handshake_to_auth 1
else
    record_reg sshd_handshake_to_auth 0 \
        "sshd did not complete a handshake on port 22 — service is down or broken; last: $PROBE"
fi

###############################################################################
# PoC: attempt each default credential against the LIVE daemon.
###############################################################################
if [ "$UP" = "1" ]; then
    CRED_DETAIL=""
    for pair in $DEFAULT_CREDS; do
        U="${pair%%:*}"; P="${pair##*:}"
        id "$U" >/dev/null 2>&1 || continue
        OUT=$(try_login "$U" "$P") || true
        if echo "$OUT" | grep -q "LOGIN_OK"; then
            CRED_DETAIL="SSH login succeeded as '$U' with default password '$P' — the account is still trivially compromised"
            break
        fi
    done

    if [ -n "$CRED_DETAIL" ]; then
        record_poc default_creds_rejected 0 "$CRED_DETAIL"
    else
        record_poc default_creds_rejected 1
    fi
else
    echo "  [SKIP] (poc) default_creds_rejected: sshd is unreachable, so every login"
    echo "         fails regardless of the credential policy. Left unrecorded so that"
    echo "         killing the service cannot read as closing the vulnerability."
fi

verify_finish
