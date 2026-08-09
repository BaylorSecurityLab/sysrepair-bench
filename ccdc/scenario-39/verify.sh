#!/bin/bash
# Scenario 39: /etc/shadow world-readable
#
# PoC checks:        /etc/shadow is not world-readable, has sane mode/ownership,
#                    an unprivileged user really cannot read it, and no
#                    world-readable copy of the hash database is lying about
# Regression checks: user lookup, sshd up, and real password authentication
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "locked down /etc/shadow but broke every login" is reported
# as security_pass=true / regression_pass=false rather than collapsing into a
# bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC Test: /etc/shadow should not be world-readable ---
PERMS=$(stat -c "%a" /etc/shadow 2>/dev/null || true)
OWNER=$(stat -c "%U:%G" /etc/shadow 2>/dev/null || true)

# Check that others can't read it (last digit should be 0)
OTHERS_PERM=${PERMS: -1}
if [[ "$OTHERS_PERM" != "0" ]]; then
    record_poc shadow_not_world_readable 0 "/etc/shadow is world-readable (permissions: ${PERMS:-unknown})"
else
    record_poc shadow_not_world_readable 1
fi

# Check permissions are correct (should be 640 or 600)
if [[ "$PERMS" == "640" ]] || [[ "$PERMS" == "600" ]]; then
    record_poc shadow_permissions_correct 1
else
    record_poc shadow_permissions_correct 0 "/etc/shadow has unexpected permissions (${PERMS:-unknown}, expected 640 or 600)"
fi

# Check ownership
if [[ "$OWNER" == "root:shadow" ]] || [[ "$OWNER" == "root:root" ]]; then
    record_poc shadow_ownership_correct 1
else
    record_poc shadow_ownership_correct 0 "/etc/shadow has wrong ownership (${OWNER:-unknown})"
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
        record_poc unprivileged_read_denied 0 "unprivileged user '$PROBE_USER' can still read /etc/shadow"
    else
        record_poc unprivileged_read_denied 1
    fi

    # The same must hold for any world-readable copy of the hashes left lying about.
    LEAKED=$(find /etc /tmp /var/tmp /home /root -xdev -maxdepth 3 -type f -perm -o+r \
                  \( -name 'shadow' -o -name 'shadow-' -o -name 'shadow.bak' -o -name 'shadow.orig' \) \
                  2>/dev/null | head -5 || true)
    if [ -n "$LEAKED" ]; then
        record_poc no_world_readable_shadow_copy 0 "world-readable copies of the shadow database exist"
        echo "$LEAKED" | sed 's/^/  /'
    else
        record_poc no_world_readable_shadow_copy 1
    fi
else
    record_poc unprivileged_read_denied 0 "no unprivileged account available for the read probe"
fi

# --- Regression Test: Authentication should still work ---
# Check that users can still be looked up
if id sysadmin > /dev/null 2>&1; then
    record_reg user_lookup_works 1
else
    record_reg user_lookup_works 0 "user lookup failed"
fi

# Check sshd is still running.
# This verifier deliberately does NOT start sshd. The image CMD boots it (see
# .preserve-cmd), so it is already up when grading starts; starting it here
# would mask an agent that killed or broke SSH while re-permissioning
# /etc/shadow. A dead sshd is a FAILURE.
if pgrep -x sshd > /dev/null 2>&1; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd is not running"
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
    record_reg sysadmin_can_authenticate 1
    echo "  [Regression] INFO: authentication path used: $AUTH_METHOD"
    # Negative control: a wrong password must NOT succeed.
    if [ "$AUTH_METHOD" = "ssh" ]; then
        WRONG=$(ssh_login sysadmin definitely-not-the-password || true)
    else
        WRONG=$(su_login sysadmin definitely-not-the-password || true)
    fi
    if echo "$WRONG" | grep -qx "sysadmin"; then
        record_reg wrong_password_rejected 0 "authentication accepted a WRONG password - the auth stack is broken open"
    else
        record_reg wrong_password_rejected 1
    fi
else
    record_reg sysadmin_can_authenticate 0 "sysadmin can no longer authenticate - the PAM/shadow auth stack is broken"
fi

verify_finish
