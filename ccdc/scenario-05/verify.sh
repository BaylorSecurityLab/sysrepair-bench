#!/bin/bash
# Scenario 05: SSH password auth with no key restriction
# Verification: PoC should fail (pubkey enabled) AND functionality test should pass

PASS=true

# --- PoC Test: PubkeyAuthentication should be enabled ---
PUBKEY=$(sshd -T 2>/dev/null | grep -i "^pubkeyauthentication" | awk '{print $2}')
if [ -z "$PUBKEY" ]; then
    PUBKEY=$(grep -i "^PubkeyAuthentication" /etc/ssh/sshd_config | tail -1 | awk '{print $2}')
fi

if [[ "$PUBKEY" == "no" ]]; then
    echo "FAIL [PoC]: PubkeyAuthentication is still disabled"
    PASS=false
else
    echo "PASS [PoC]: PubkeyAuthentication is enabled"
fi

# --- PoC Test: Password-only auth should not be the sole method ---
# At minimum, pubkey should be enabled. Ideally password auth is disabled.
PWAUTH=$(sshd -T 2>/dev/null | grep -i "^passwordauthentication" | awk '{print $2}')
if [ -z "$PWAUTH" ]; then
    PWAUTH=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config | tail -1 | awk '{print $2}')
fi

if [[ "$PUBKEY" != "no" ]] && [[ "$PWAUTH" == "no" ]]; then
    echo "PASS [PoC]: PasswordAuthentication disabled, PubkeyAuthentication enabled (ideal)"
elif [[ "$PUBKEY" != "no" ]]; then
    echo "PASS [PoC]: PubkeyAuthentication enabled (password auth still on but acceptable)"
else
    echo "FAIL [PoC]: System still relies on password-only authentication"
    PASS=false
fi

# --- PoC Behavioral Test (RUNTIME): prove it against the LIVE daemon ---
#
# `sshd -T` and the sshd_config greps above only PARSE THE CONFIG FILE. A model
# that edits sshd_config but never restarts sshd leaves the running daemon
# password-only and fully vulnerable - that state MUST fail. Everything below
# talks to the daemon over the wire on port 22 instead of reading a file.
#
# The image CMD boots sshd with the vulnerable config (see .preserve-cmd), so a
# daemon is ALWAYS expected here. verify.sh must never start or restart it: a
# fresh daemon would pick up the agent's edited config and mask the very case
# we are trying to catch. A dead daemon is a failure.
if ! pgrep -x sshd > /dev/null 2>&1; then
    echo "FAIL [PoC]: sshd is not running - cannot verify authentication behaviour"
    PASS=false
else
    # (1) Ask the RUNNING daemon which authentication methods it actually
    #     offers. This is the daemon's own userauth banner, not a config file.
    ADVERTISED=$(ssh -v -o PreferredAuthentications=none -o BatchMode=yes \
        -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        sysadmin@127.0.0.1 true 2>&1 \
        | sed -n 's/.*Authentications that can continue: //p' | head -1)
    echo "INFO [PoC]: live daemon advertises auth methods: ${ADVERTISED:-<none>}"

    if [ -z "$ADVERTISED" ]; then
        echo "FAIL [PoC]: could not negotiate with the live sshd on 127.0.0.1:22"
        PASS=false
    else
        # (2) Perform an ACTUAL public-key login against the running daemon.
        #     A throwaway key is installed for sysadmin and removed again; the
        #     previous authorized_keys is checksummed and restored byte-for-byte.
        SSHHOME=$(getent passwd sysadmin | cut -d: -f6)
        AK="$SSHHOME/.ssh/authorized_keys"
        PROBE_KEY=/tmp/.pubkey_probe.$$
        AK_BACKUP=/tmp/.ak_backup.$$
        AK_EXISTED=0
        AK_SUM_BEFORE=""
        if [ -f "$AK" ]; then
            AK_EXISTED=1
            cp -p "$AK" "$AK_BACKUP"
            AK_SUM_BEFORE=$(md5sum "$AK" | awk '{print $1}')
        fi

        ssh-keygen -q -t ed25519 -N '' -f "$PROBE_KEY" >/dev/null 2>&1
        mkdir -p "$SSHHOME/.ssh"
        cat "$PROBE_KEY.pub" >> "$AK"
        chown -R sysadmin:sysadmin "$SSHHOME/.ssh" 2>/dev/null
        chmod 700 "$SSHHOME/.ssh" 2>/dev/null
        chmod 600 "$AK" 2>/dev/null

        PK_RESULT=$(ssh -i "$PROBE_KEY" -o IdentitiesOnly=yes \
            -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes \
            -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            sysadmin@127.0.0.1 'echo PUBKEY_LOGIN_OK' 2>&1 || true)

        # --- restore exact prior state ---
        if [ "$AK_EXISTED" -eq 1 ]; then
            cp -p "$AK_BACKUP" "$AK"
            AK_SUM_AFTER=$(md5sum "$AK" | awk '{print $1}')
            if [ "$AK_SUM_BEFORE" != "$AK_SUM_AFTER" ]; then
                echo "WARN [PoC]: authorized_keys checksum mismatch after probe"
            fi
        else
            rm -f "$AK"
        fi
        rm -f "$AK_BACKUP" "$PROBE_KEY" "$PROBE_KEY.pub"

        if echo "$PK_RESULT" | grep -q 'PUBKEY_LOGIN_OK'; then
            echo "PASS [PoC]: live daemon accepted a real public-key login"
        else
            echo "FAIL [PoC]: live daemon REFUSED public-key authentication"
            echo "            (sshd_config may say PubkeyAuthentication yes, but the"
            echo "             running sshd was never restarted - got: ${PK_RESULT##*$'\n'})"
            PASS=false
        fi

        # (3) If the config claims password auth is off, the RUNNING daemon must
        #     not still be advertising 'password' to clients.
        if [[ "$PWAUTH" == "no" ]]; then
            if echo "$ADVERTISED" | tr ',' '\n' | grep -qx 'password'; then
                echo "FAIL [PoC]: live daemon still offers password authentication"
                echo "            (config says PasswordAuthentication no - sshd not restarted)"
                PASS=false
            else
                echo "PASS [PoC]: live daemon no longer offers password authentication"
            fi
        else
            echo "INFO [PoC]: PasswordAuthentication still on (acceptable); pubkey is live"
        fi
    fi
fi

# --- Regression Test: SSH service should still be functional ---
if pgrep -x sshd > /dev/null 2>&1; then
    echo "PASS [Regression]: sshd process is running"
else
    # Do NOT start it here - the service is supposed to be up already and
    # starting it would hide a service the agent stopped or broke.
    echo "FAIL [Regression]: sshd is not running"
    PASS=false
fi

if sshd -t 2>/dev/null; then
    echo "PASS [Regression]: sshd configuration is valid"
else
    echo "FAIL [Regression]: sshd configuration is invalid"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
