#!/bin/bash
# Scenario 27: Telnet server running
# Verification: PoC should fail (telnet removed) AND functionality test should pass (SSH available)

PASS=true

# --- PoC Test: Telnet should not be installed or running ---
# BROKEN BEFORE: only the `telnetd` transitional dummy package was checked.
# The package that actually ships /usr/sbin/telnetd is inetutils-telnetd, so
# removing just the dummy left a fully working telnet server on the box.
for PKG in telnetd inetutils-telnetd telnetd-ssl; do
    if dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        echo "FAIL [PoC]: $PKG package is still installed"
        PASS=false
    else
        echo "PASS [PoC]: $PKG package is removed"
    fi
done

if pgrep -x xinetd > /dev/null 2>&1 || pgrep -f in.telnetd > /dev/null 2>&1; then
    echo "FAIL [PoC]: telnet/xinetd service is still running"
    PASS=false
else
    echo "PASS [PoC]: telnet/xinetd service is not running"
fi

# BROKEN BEFORE: the port-23 listener check used `ss`, but iproute2 is NOT in
# this image, so `ss` was always "command not found", the grep never matched and
# the check could never fire. It is now done two ways with tools that do exist:
#   1. /proc/net/tcp + /proc/net/tcp6 (port 23 = hex 0017, state 0A = LISTEN)
#   2. a bash /dev/tcp connect attempt, guarded by `timeout`
# The image CMD now boots xinetd (see .preserve-cmd), so a still-enabled telnet
# service is normally already listening. We ALSO deliberately resurrect xinetd
# when it is down but still installed and still enabled: an agent that merely
# stops the daemon without disabling/removing the service has not fixed
# anything, and a reboot would re-expose telnet. This makes the check stronger,
# not weaker.
#
# It is the only place this verifier mutates the box, so the mutation is undone
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

port23_listening() {
    # LISTEN sockets bound to :23 in either the v4 or the v6 table
    awk '$4 == "0A" && $2 ~ /:0017$/ { found = 1 } END { exit !found }' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null && return 0
    # Fallback: actually try to open a connection to it
    timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/23' 2>/dev/null && return 0
    return 1
}

if port23_listening; then
    echo "FAIL [PoC]: Port 23 (telnet) is still listening"
    PASS=false
else
    echo "PASS [PoC]: Port 23 is not listening"
fi

# Leave the box as we found it - only undo the xinetd WE started.
_xinetd_probe_cleanup

# --- Regression Test: SSH should be available as replacement ---
# BROKEN BEFORE: this only ran `dpkg -l openssh-server`, so a completely broken
# sshd (missing host keys, unusable config, no working authentication) still
# passed and the "secure replacement for telnet" was never actually exercised.
# It now confirms sshd is RUNNING and bound to port 22, and performs a REAL
# authenticated login as sysadmin that runs a command and returns its output.
#
# This verifier deliberately does NOT start sshd for you. Installing
# openssh-server without leaving it running is not a working replacement for
# telnet, so a dead sshd is a FAILURE.
if ! dpkg -l openssh-server 2>/dev/null | grep -q "^ii"; then
    echo "FAIL [Regression]: openssh-server is not installed (no secure remote access)"
    PASS=false
elif [ ! -x /usr/sbin/sshd ] || ! command -v ssh > /dev/null 2>&1; then
    echo "FAIL [Regression]: sshd or the ssh client binary is missing"
    PASS=false
else
    if ! pgrep -x sshd > /dev/null 2>&1; then
        echo "FAIL [Regression]: sshd is not running (openssh-server installed but never started)"
        PASS=false
    fi

    if ! awk '$4 == "0A" && $2 ~ /:0016$/ { f = 1 } END { exit !f }' \
            /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
        echo "FAIL [Regression]: sshd is not listening on port 22"
        PASS=false
    else
        # Real authentication: install a throwaway key for sysadmin, log in,
        # run a command, then remove the key again.
        #
        # Cleanup runs from a trap, NOT inline: if this script is killed between
        # installing the key and removing it (harness timeout, cancelled run),
        # inline cleanup never executes and a WORKING BACKDOOR KEY is left behind
        # in the box being graded. The trap fires on EXIT/INT/TERM so the box is
        # always handed back exactly as it was found.
        SSH_TMP=$(mktemp -d)
        SSH_HOME=$(getent passwd sysadmin | cut -d: -f6)
        SSH_OK=false
        SSH_DIR_CREATED=false
        SSH_AK_EXISTED=false

        _ssh_probe_cleanup() {
            [ -n "${SSH_HOME:-}" ] || { rm -rf "$SSH_TMP" 2>/dev/null; return; }
            if [ "$SSH_AK_EXISTED" = true ] && [ -f "$SSH_TMP/ak.orig" ]; then
                # Restore the file byte-for-byte, preserving mode/owner.
                cp -p "$SSH_TMP/ak.orig" "$SSH_HOME/.ssh/authorized_keys" 2>/dev/null
            else
                rm -f "$SSH_HOME/.ssh/authorized_keys" 2>/dev/null
            fi
            if [ "$SSH_DIR_CREATED" = true ]; then
                rmdir "$SSH_HOME/.ssh" 2>/dev/null
            fi
            rm -rf "$SSH_TMP" 2>/dev/null
            _xinetd_probe_cleanup
        }
        trap _ssh_probe_cleanup EXIT INT TERM

        if [ -n "$SSH_HOME" ] && ssh-keygen -q -t ed25519 -N "" -f "$SSH_TMP/vk" > /dev/null 2>&1; then
            [ -d "$SSH_HOME/.ssh" ] || SSH_DIR_CREATED=true
            mkdir -p "$SSH_HOME/.ssh"
            if [ -f "$SSH_HOME/.ssh/authorized_keys" ]; then
                SSH_AK_EXISTED=true
                cp -p "$SSH_HOME/.ssh/authorized_keys" "$SSH_TMP/ak.orig"
            fi
            # Defence in depth: the trap below cannot fire if this script is
            # SIGKILLed, so constrain the probe key at install time. Forced
            # command + localhost-only + no forwarding/pty means that even a
            # leaked key can do nothing except echo the probe token from
            # 127.0.0.1 - it is not a usable back door.
            printf 'command="echo SSH_VERIFY_OK",from="127.0.0.1",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty %s\n' \
                "$(cat "$SSH_TMP/vk.pub")" >> "$SSH_HOME/.ssh/authorized_keys"
            chown -R sysadmin: "$SSH_HOME/.ssh" 2>/dev/null
            chmod 700 "$SSH_HOME/.ssh"
            chmod 600 "$SSH_HOME/.ssh/authorized_keys"

            SSH_OUT=$(timeout 30 ssh -i "$SSH_TMP/vk" -o BatchMode=yes \
                -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o ConnectTimeout=10 sysadmin@127.0.0.1 \
                'echo SSH_VERIFY_OK' 2>/dev/null)
            [ "$SSH_OUT" = "SSH_VERIFY_OK" ] && SSH_OK=true
        fi

        _ssh_probe_cleanup
        trap - EXIT INT TERM

        if $SSH_OK; then
            echo "PASS [Regression]: sshd accepts a real authenticated session as sysadmin"
        else
            echo "FAIL [Regression]: could not authenticate to sshd over SSH (service is broken)"
            PASS=false
        fi
    fi
fi

# Users should still exist
if id sysadmin > /dev/null 2>&1; then
    echo "PASS [Regression]: sysadmin user still exists"
else
    echo "FAIL [Regression]: sysadmin user is missing"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
