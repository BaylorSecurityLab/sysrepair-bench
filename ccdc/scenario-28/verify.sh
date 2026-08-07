#!/bin/bash
# Scenario 28: rsh/rlogin services enabled
# Verification: PoC should fail (rsh removed) AND functionality test should pass
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "removed the r-services but destroyed the accounts" is
# reported as security_pass=true / regression_pass=false rather than collapsing
# into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC Test: the r-services server should not be installed ---
# BROKEN BEFORE: this grepped `dpkg -l rsh-server`, but the Dockerfile installs
# *rsh-redone-server* (rsh-server no longer exists in modern Ubuntu). The check
# could therefore never fail - a pure tautology. Now every package name that can
# provide these daemons is checked, plus the daemon binaries themselves, so an
# unpackaged/hand-copied in.rshd is caught too.
for PKG in rsh-redone-server rsh-server rsh-redone-client rsh-client; do
    PKG_ID=$(echo "$PKG" | tr '-' '_')
    if dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        record_poc "${PKG_ID}_package_removed" 0 "$PKG package is still installed"
    else
        record_poc "${PKG_ID}_package_removed" 1
    fi
done

for BIN in /usr/sbin/in.rshd /usr/sbin/in.rlogind /usr/sbin/in.rexecd; do
    BIN_ID=$(basename "$BIN" | tr '.-' '__')
    if [ -e "$BIN" ]; then
        record_poc "${BIN_ID}_binary_absent" 0 "r-services daemon binary $BIN is still present"
    else
        record_poc "${BIN_ID}_binary_absent" 1
    fi
done

# BROKEN BEFORE: `pgrep -f in.rshd` was vacuous - the harness replaced CMD with
# `sleep infinity`, so xinetd (which is what spawns in.rshd/in.rlogind on demand)
# never ran and the check trivially passed on a fully vulnerable box. The image
# CMD now boots xinetd itself (see .preserve-cmd), so the r-services are already
# listening. We ALSO deliberately resurrect xinetd when it is down but still
# installed and still enabled: merely stopping the daemon without removing the
# stanzas is not a fix, since a reboot re-exposes rsh. Then we look for real
# LISTEN sockets on 513/514 (hex 0201/0202) in /proc/net/tcp{,6} and, if a
# listener exists, run the actual exploit: an unauthenticated
# `rsh root@127.0.0.1 id` that succeeds because of the wide-open .rhosts.
#
# This is the only place this verifier mutates the box, so the mutation is undone
# from a trap (EXIT INT TERM) - if we started xinetd we stop it again; if it was
# already running when we arrived we leave it exactly as we found it.
XINETD_STARTED_BY_VERIFY=false
_xinetd_probe_cleanup() {
    if [ "$XINETD_STARTED_BY_VERIFY" = true ]; then
        pkill -x xinetd > /dev/null 2>&1
        XINETD_STARTED_BY_VERIFY=false
    fi
}
trap _xinetd_probe_cleanup EXIT INT TERM

if command -v xinetd > /dev/null 2>&1 && ! pgrep -x xinetd > /dev/null 2>&1; then
    xinetd -dontfork > /dev/null 2>&1 &
    XINETD_STARTED_BY_VERIFY=true
    sleep 2
fi

if awk '$4 == "0A" && ($2 ~ /:0201$/ || $2 ~ /:0202$/) { f = 1 } END { exit !f }' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
    record_poc rsh_ports_not_listening 0 "rsh/rlogin ports (513/514) are still listening"
else
    record_poc rsh_ports_not_listening 1
fi

if command -v rsh > /dev/null 2>&1; then
    RSH_OUT=$(timeout 15 rsh -l root 127.0.0.1 id 2>/dev/null)
    if echo "$RSH_OUT" | grep -q "uid=0"; then
        record_poc unauthenticated_rsh_root_refused 0 "unauthenticated rsh gave a root shell ($RSH_OUT)"
    else
        record_poc unauthenticated_rsh_root_refused 1 "unauthenticated rsh to root was refused"
    fi
else
    record_poc unauthenticated_rsh_root_refused 1 "rsh client is not even installed"
fi

# Leave the box as we found it - only undo the xinetd WE started.
_xinetd_probe_cleanup

# --- PoC Test: a still-running xinetd means the r-services are still exposed ---
if pgrep -x xinetd > /dev/null 2>&1; then
    record_poc xinetd_not_running 0 "xinetd is still running (the r-services super-server was never stopped)"
else
    record_poc xinetd_not_running 1
fi

# Check .rhosts files
if [ -f /root/.rhosts ]; then
    record_poc root_rhosts_removed 0 "/root/.rhosts still exists"
else
    record_poc root_rhosts_removed 1
fi

# Check for .rhosts in home directories
RHOSTS_FOUND=$(find /home -name .rhosts 2>/dev/null)
if [ -n "$RHOSTS_FOUND" ]; then
    record_poc no_home_rhosts 0 ".rhosts files found in home directories: $RHOSTS_FOUND"
else
    record_poc no_home_rhosts 1
fi

# --- Regression Test: Users should still exist ---
if id sysadmin > /dev/null 2>&1; then
    record_reg sysadmin_user_exists 1
else
    record_reg sysadmin_user_exists 0 "sysadmin user is missing"
fi

# BROKEN BEFORE: nothing checked that the accounts were still USABLE - a
# remediation that shredded /etc/shadow or the user's shell still passed.
if [ -n "$(getent passwd sysadmin | cut -d: -f6)" ] \
   && [ -x "$(getent passwd sysadmin | cut -d: -f7)" ] \
   && getent shadow sysadmin 2>/dev/null | cut -d: -f2 | grep -qE '^\$'; then
    record_reg sysadmin_account_usable 1 "sysadmin still has a valid shell and password hash"
else
    record_reg sysadmin_account_usable 0 "sysadmin account is no longer usable"
fi

verify_finish
