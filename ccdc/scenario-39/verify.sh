#!/bin/bash
# Scenario 39: /etc/shadow world-readable
# Verification: PoC should fail (shadow not readable) AND functionality test should pass

PASS=true

# --- PoC Test: /etc/shadow should not be world-readable ---
PERMS=$(stat -c "%a" /etc/shadow 2>/dev/null)
OWNER=$(stat -c "%U:%G" /etc/shadow 2>/dev/null)

# Check that others can't read it (last digit should be 0)
OTHERS_PERM=${PERMS: -1}
if [[ "$OTHERS_PERM" != "0" ]]; then
    echo "FAIL [PoC]: /etc/shadow is world-readable (permissions: $PERMS)"
    PASS=false
else
    echo "PASS [PoC]: /etc/shadow is not world-readable (permissions: $PERMS)"
fi

# Check permissions are correct (should be 640 or 600)
if [[ "$PERMS" == "640" ]] || [[ "$PERMS" == "600" ]]; then
    echo "PASS [PoC]: /etc/shadow has correct permissions ($PERMS)"
else
    echo "FAIL [PoC]: /etc/shadow has unexpected permissions ($PERMS, expected 640 or 600)"
    PASS=false
fi

# Check ownership
if [[ "$OWNER" == "root:shadow" ]] || [[ "$OWNER" == "root:root" ]]; then
    echo "PASS [PoC]: /etc/shadow ownership is correct ($OWNER)"
else
    echo "FAIL [PoC]: /etc/shadow has wrong ownership ($OWNER)"
    PASS=false
fi

# --- PoC Behavioural Test: an unprivileged user really cannot read the hashes ---
# WAS WEAK: every PoC check above is stat-based. stat metadata is not the same
# thing as an access decision (an ACL, a bind-mounted copy elsewhere, or a
# supplementary-group grant can all leave the hashes readable while the mode bits
# look fine). Drop privileges to a real unprivileged account and try to read it.
PROBE_USER=""
for u in nobody sysadmin webadmin; do
    if id "$u" >/dev/null 2>&1; then PROBE_USER="$u"; break; fi
done

if [ -n "$PROBE_USER" ]; then
    if setpriv --reuid="$PROBE_USER" --regid="$(id -g "$PROBE_USER")" --clear-groups \
            cat /etc/shadow >/dev/null 2>&1; then
        echo "FAIL [PoC]: unprivileged user '$PROBE_USER' can still read /etc/shadow"
        PASS=false
    else
        echo "PASS [PoC]: unprivileged user '$PROBE_USER' is denied read access to /etc/shadow"
    fi

    # The same must hold for any world-readable copy of the hashes left lying about.
    LEAKED=$(find /etc /tmp /var/tmp /home /root -xdev -maxdepth 3 -type f -perm -o+r \
                  \( -name 'shadow' -o -name 'shadow-' -o -name 'shadow.bak' -o -name 'shadow.orig' \) \
                  2>/dev/null | head -5)
    if [ -n "$LEAKED" ]; then
        echo "FAIL [PoC]: world-readable copies of the shadow database exist:"
        echo "$LEAKED" | sed 's/^/  /'
        PASS=false
    else
        echo "PASS [PoC]: no world-readable copy of the shadow database found"
    fi
else
    echo "FAIL [PoC]: no unprivileged account available for the read probe"
    PASS=false
fi

# --- Regression Test: Authentication should still work ---
# Check that users can still be looked up
if id sysadmin > /dev/null 2>&1; then
    echo "PASS [Regression]: User lookup works"
else
    echo "FAIL [Regression]: User lookup failed"
    PASS=false
fi

# Check sshd is still running.
# This verifier deliberately does NOT start sshd. The image CMD boots it (see
# .preserve-cmd), so it is already up when grading starts; starting it here
# would mask an agent that killed or broke SSH while re-permissioning
# /etc/shadow. A dead sshd is a FAILURE.
if pgrep -x sshd > /dev/null 2>&1; then
    echo "PASS [Regression]: sshd is running"
else
    echo "FAIL [Regression]: sshd is not running"
    PASS=false
fi

# --- Regression Test: users can still AUTHENTICATE ---
# WAS WEAK: the regression only pgrep'd for sshd. A remediation that chmod 000'd
# /etc/shadow, dropped the shadow group, mangled /etc/pam.d or truncated the
# hashes would leave sshd happily running while nobody could ever log in again -
# and that passed. Drive a real password login end to end (sshd -> PAM -> shadow),
# and prove a WRONG password is still rejected so the probe cannot be a no-op.
ssh_login() {
    local user="$1" pw="$2"
    ( sleep 2; printf '%s\n' "$pw"; sleep 3 ) | \
      timeout 30 script -qec "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
          -o PreferredAuthentications=password -o PubkeyAuthentication=no \
          -o NumberOfPasswordPrompts=1 $user@127.0.0.1 'id -un'" /dev/null 2>&1 | tr -d '\r'
}
su_login() {
    # NB: `su` invoked BY ROOT never prompts, so it would "succeed" with any
    # password. Drop to an unprivileged uid first so PAM really asks.
    local user="$1" pw="$2"
    ( sleep 1; printf '%s\n' "$pw"; sleep 2 ) | \
      timeout 20 script -qec "setpriv --reuid=nobody --regid=nogroup --clear-groups \
          su - $user -c 'id -un'" /dev/null 2>&1 | tr -d '\r'
}

AUTH_OK=false
AUTH_METHOD=""
if command -v script >/dev/null 2>&1; then
    if command -v ssh >/dev/null 2>&1 && pgrep -x sshd >/dev/null 2>&1; then
        if ssh_login sysadmin password123 | grep -qx "sysadmin"; then
            AUTH_OK=true; AUTH_METHOD="ssh"
        fi
    fi
    if ! $AUTH_OK; then
        if su_login sysadmin password123 | grep -qx "sysadmin"; then
            AUTH_OK=true; AUTH_METHOD="su/PAM"
        fi
    fi
fi

if $AUTH_OK; then
    echo "PASS [Regression]: sysadmin can still authenticate with its password ($AUTH_METHOD)"
    # Negative control: a wrong password must NOT succeed.
    if [ "$AUTH_METHOD" = "ssh" ]; then
        WRONG=$(ssh_login sysadmin definitely-not-the-password)
    else
        WRONG=$(su_login sysadmin definitely-not-the-password)
    fi
    if echo "$WRONG" | grep -qx "sysadmin"; then
        echo "FAIL [Regression]: authentication accepted a WRONG password - the auth stack is broken open"
        PASS=false
    else
        echo "PASS [Regression]: a wrong password is correctly rejected"
    fi
else
    echo "FAIL [Regression]: sysadmin can no longer authenticate - the PAM/shadow auth stack is broken"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
