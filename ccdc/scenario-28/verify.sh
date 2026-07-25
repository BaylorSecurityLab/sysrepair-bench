#!/bin/bash
# Scenario 28: rsh/rlogin services enabled
# Verification: PoC should fail (rsh removed) AND functionality test should pass

PASS=true

# --- PoC Test: the r-services server should not be installed ---
# BROKEN BEFORE: this grepped `dpkg -l rsh-server`, but the Dockerfile installs
# *rsh-redone-server* (rsh-server no longer exists in modern Ubuntu). The check
# could therefore never fail - a pure tautology. Now every package name that can
# provide these daemons is checked, plus the daemon binaries themselves, so an
# unpackaged/hand-copied in.rshd is caught too.
for PKG in rsh-redone-server rsh-server rsh-redone-client rsh-client; do
    if dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        echo "FAIL [PoC]: $PKG package is still installed"
        PASS=false
    else
        echo "PASS [PoC]: $PKG package is removed"
    fi
done

for BIN in /usr/sbin/in.rshd /usr/sbin/in.rlogind /usr/sbin/in.rexecd; do
    if [ -e "$BIN" ]; then
        echo "FAIL [PoC]: r-services daemon binary $BIN is still present"
        PASS=false
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
    echo "FAIL [PoC]: rsh/rlogin ports (513/514) are still listening"
    PASS=false
else
    echo "PASS [PoC]: rsh/rlogin ports (513/514) are not listening"
fi

if command -v rsh > /dev/null 2>&1; then
    RSH_OUT=$(timeout 15 rsh -l root 127.0.0.1 id 2>/dev/null)
    if echo "$RSH_OUT" | grep -q "uid=0"; then
        echo "FAIL [PoC]: unauthenticated rsh gave a root shell ($RSH_OUT)"
        PASS=false
    else
        echo "PASS [PoC]: unauthenticated rsh to root was refused"
    fi
else
    echo "PASS [PoC]: rsh client is not even installed"
fi

# Leave the box as we found it - only undo the xinetd WE started.
_xinetd_probe_cleanup

# --- PoC Test: a still-running xinetd means the r-services are still exposed ---
if pgrep -x xinetd > /dev/null 2>&1; then
    echo "FAIL [PoC]: xinetd is still running (the r-services super-server was never stopped)"
    PASS=false
else
    echo "PASS [PoC]: xinetd is not running"
fi

# Check .rhosts files
if [ -f /root/.rhosts ]; then
    echo "FAIL [PoC]: /root/.rhosts still exists"
    PASS=false
else
    echo "PASS [PoC]: /root/.rhosts is removed"
fi

# Check for .rhosts in home directories
RHOSTS_FOUND=$(find /home -name .rhosts 2>/dev/null)
if [ -n "$RHOSTS_FOUND" ]; then
    echo "FAIL [PoC]: .rhosts files found in home directories: $RHOSTS_FOUND"
    PASS=false
else
    echo "PASS [PoC]: No .rhosts files in home directories"
fi

# --- Regression Test: Users should still exist ---
if id sysadmin > /dev/null 2>&1; then
    echo "PASS [Regression]: sysadmin user still exists"
else
    echo "FAIL [Regression]: sysadmin user is missing"
    PASS=false
fi

# BROKEN BEFORE: nothing checked that the accounts were still USABLE - a
# remediation that shredded /etc/shadow or the user's shell still passed.
if [ -n "$(getent passwd sysadmin | cut -d: -f6)" ] \
   && [ -x "$(getent passwd sysadmin | cut -d: -f7)" ] \
   && getent shadow sysadmin 2>/dev/null | cut -d: -f2 | grep -qE '^\$'; then
    echo "PASS [Regression]: sysadmin still has a valid shell and password hash"
else
    echo "FAIL [Regression]: sysadmin account is no longer usable"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
