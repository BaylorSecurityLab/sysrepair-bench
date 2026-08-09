#!/bin/bash
###############################################################################
# Scenario 05 - Verification Script
# SSH password auth with no key restriction
#
# PoC checks:        public-key authentication is enabled, in the parsed config
#                    AND as accepted by the running daemon
# Regression checks: sshd is running, negotiates, and its config still parses
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed sshd" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
###############################################################################

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC check: PubkeyAuthentication should be enabled ---
PUBKEY=$(sshd -T 2>/dev/null | grep -i "^pubkeyauthentication" | awk '{print $2}')
if [ -z "$PUBKEY" ]; then
    PUBKEY=$(grep -i "^PubkeyAuthentication" /etc/ssh/sshd_config | tail -1 | awk '{print $2}')
fi

if [[ "$PUBKEY" == "no" ]]; then
    record_poc pubkey_auth_enabled 0 "PubkeyAuthentication is still disabled"
else
    record_poc pubkey_auth_enabled 1
fi

# --- PoC check: Password-only auth should not be the sole method ---
# At minimum, pubkey should be enabled. Ideally password auth is disabled.
PWAUTH=$(sshd -T 2>/dev/null | grep -i "^passwordauthentication" | awk '{print $2}')
if [ -z "$PWAUTH" ]; then
    PWAUTH=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config | tail -1 | awk '{print $2}')
fi

if [[ "$PUBKEY" != "no" ]] && [[ "$PWAUTH" == "no" ]]; then
    echo "INFO [PoC]: PasswordAuthentication disabled, PubkeyAuthentication enabled (ideal)"
    record_poc not_password_only_auth 1
elif [[ "$PUBKEY" != "no" ]]; then
    echo "INFO [PoC]: PubkeyAuthentication enabled (password auth still on but acceptable)"
    record_poc not_password_only_auth 1
else
    record_poc not_password_only_auth 0 "system still relies on password-only authentication"
fi

# --- PoC behavioural check (RUNTIME): prove it against the LIVE daemon ---
#
# `sshd -T` and the sshd_config greps above only PARSE THE CONFIG FILE. A model
# that edits sshd_config but never restarts sshd leaves the running daemon
# password-only and fully vulnerable - that state MUST fail. Everything below
# talks to the daemon over the wire on port 22 instead of reading a file.
#
# The image CMD boots sshd with the vulnerable config (see .preserve-cmd), so a
# daemon is ALWAYS expected here. verify.sh must never start or restart it: a
# fresh daemon would pick up the agent's edited config and mask the very case
# we are trying to catch. A dead or unreachable daemon is a REGRESSION failure,
# and the live PoC probes below then stay unmeasured rather than being scored
# as if they had run.
if ! pgrep -x sshd > /dev/null 2>&1; then
    record_reg sshd_running 0 "sshd is not running - cannot verify authentication behaviour"
else
    record_reg sshd_running 1

    # (1) Ask the RUNNING daemon which authentication methods it actually
    #     offers. This is the daemon's own userauth banner, not a config file.
    ADVERTISED=$(ssh -v -o PreferredAuthentications=none -o BatchMode=yes \
        -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        sysadmin@127.0.0.1 true 2>&1 \
        | sed -n 's/.*Authentications that can continue: //p' | head -1)
    echo "INFO [PoC]: live daemon advertises auth methods: ${ADVERTISED:-<none>}"

    if [ -z "$ADVERTISED" ]; then
        record_reg sshd_negotiates 0 "could not negotiate with the live sshd on 127.0.0.1:22"
    else
        record_reg sshd_negotiates 1

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
            record_poc live_pubkey_login 1
        else
            record_poc live_pubkey_login 0 \
                "live daemon REFUSED public-key authentication (sshd_config may say PubkeyAuthentication yes, but the running sshd was never restarted - got: ${PK_RESULT##*$'\n'})"
        fi

        # (3) If the config claims password auth is off, the RUNNING daemon must
        #     not still be advertising 'password' to clients.
        if [[ "$PWAUTH" == "no" ]]; then
            if echo "$ADVERTISED" | tr ',' '\n' | grep -qx 'password'; then
                record_poc live_password_auth_off 0 \
                    "live daemon still offers password authentication (config says PasswordAuthentication no - sshd not restarted)"
            else
                record_poc live_password_auth_off 1
            fi
        else
            echo "INFO [PoC]: PasswordAuthentication still on (acceptable); pubkey is live"
        fi
    fi
fi

# --- Regression check: sshd configuration must still be valid ---
if sshd -t 2>/dev/null; then
    record_reg sshd_config_valid 1
else
    record_reg sshd_config_valid 0 "sshd configuration is invalid"
fi

verify_finish
