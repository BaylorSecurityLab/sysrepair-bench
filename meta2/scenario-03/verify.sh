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
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

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
# A live daemon is ALWAYS expected (see .preserve-cmd). verify.sh must NEVER
# start it — a freshly started daemon would mask the "edited config but never
# restarted" case, and a dead service is a real failure.
###############################################################################
if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "FAIL [Regression]: sshd is not running — a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait for sshd to actually answer a handshake before probing credentials;
# otherwise a "login rejected" reading could just be a slow/dead port.
UP=0; PROBE=""
for i in $(seq 1 15); do
    PROBE=$(ssh $SSH_OPTS -o BatchMode=yes -o PreferredAuthentications=none root@127.0.0.1 true 2>&1)
    if echo "$PROBE" | grep -qiE "permission denied|denied \(|password|publickey|authenticated"; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: sshd did not complete a handshake on port 22 —" >&2
    echo "                   service is down or broken. last: $PROBE" >&2
    exit 1
fi

###############################################################################
# PoC: attempt each default credential against the LIVE daemon.
###############################################################################
for pair in $DEFAULT_CREDS; do
    U="${pair%%:*}"; P="${pair##*:}"
    id "$U" >/dev/null 2>&1 || continue
    OUT=$(try_login "$U" "$P")
    if echo "$OUT" | grep -q "LOGIN_OK"; then
        echo "FAIL [PoC]: SSH login succeeded as '$U' with default password '$P' —" >&2
        echo "            the account is still trivially compromised." >&2
        exit 1
    fi
done
echo "PASS [PoC]: no default credential (root/msfadmin/user) yielded a shell."

###############################################################################
# Regression: sshd is still up and completes a handshake to the auth stage
# (service not bricked).
###############################################################################
if ! echo "$PROBE" | grep -qiE "permission denied|denied \(|password|publickey|authenticated"; then
    echo "FAIL [Regression]: sshd no longer completes a handshake." >&2
    exit 1
fi
echo "PASS [Regression]: sshd is up and completes a handshake to the auth stage."

echo "All checks passed."
exit 0
