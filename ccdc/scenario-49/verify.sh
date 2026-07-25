#!/bin/bash
# Scenario 49: Rogue SSH authorized_keys on root
# Verification: PoC should fail (rogue keys removed) AND functionality test should pass

PASS=true

# WAS THE WEAKEST CHECK IN THE SUITE: the PoC grepped the free-text COMMENT
# fields ('attacker@evil.com' / 'backdoor@malware.net'), so
#   sed -i 's/attacker@evil.com/ops@corp/' /root/.ssh/authorized_keys
# left BOTH BACKDOOR KEYS FULLY ACTIVE and still passed. Comments are cosmetic
# and attacker-controlled; the base64 KEY MATERIAL is what actually grants
# access. We now identify the planted keys by the SHA-256 of their key blob,
# so renaming (or removing) the comment changes nothing.
ROGUE_KEY_SHA256="
0ea396189d030ac9d5001d70d9a1ee274683e352b36dcf0a9b3ac258d5502e4a
d0d280ebefb9548592efea2bc528e7cd4fdc7ca1a059c843a6fe8168d2a1e475
"

# Emit the base64 key material of every key in an authorized_keys file.
# Picking the field that starts with AAAA also defeats hiding the key behind
# an options prefix (command="...",from="..." ssh-rsa AAAA... ).
key_blobs() {
    awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^AAAA[A-Za-z0-9+\/=_]+$/) print $i }' "$1" 2>/dev/null
}

blob_is_rogue() {
    local digest
    digest=$(printf '%s' "$1" | sha256sum | awk '{print $1}')
    case " $(echo $ROGUE_KEY_SHA256) " in
        *" $digest "*) return 0 ;;
    esac
    return 1
}

# --- PoC Test: Root should not have unauthorized authorized_keys ---
ROOT_KEYS_TOTAL=0
ROOT_KEYS_ROGUE=0
for ak in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2; do
    [ -f "$ak" ] || continue
    while IFS= read -r blob; do
        [ -n "$blob" ] || continue
        ROOT_KEYS_TOTAL=$((ROOT_KEYS_TOTAL + 1))
        if blob_is_rogue "$blob"; then
            ROOT_KEYS_ROGUE=$((ROOT_KEYS_ROGUE + 1))
            echo "FAIL [PoC]: known backdoor key material still authorizes root in $ak (sha256:$(printf '%s' "$blob" | sha256sum | cut -c1-16)...)"
            PASS=false
        fi
    done <<< "$(key_blobs "$ak")"
done
if [ "$ROOT_KEYS_ROGUE" -eq 0 ]; then
    echo "PASS [PoC]: no known backdoor key material in root's authorized_keys"
fi

# WAS ONLY A WARNING: leftover keys were merely reported. This image ships ZERO
# legitimate root authorized_keys (both planted entries are backdoors), so any
# surviving root key is an unaccounted-for remote-root grant and is a FAILURE.
if [ "$ROOT_KEYS_TOTAL" -gt 0 ]; then
    echo "FAIL [PoC]: $ROOT_KEYS_TOTAL SSH key(s) still authorize root login - this host has no legitimate root keys"
    PASS=false
else
    echo "PASS [PoC]: no SSH key authorizes root login"
fi

# --- PoC Test: Check other users' authorized_keys too ---
ROGUE_FOUND=false
for home_dir in /home/*/; do
    ak_file="$home_dir.ssh/authorized_keys"
    [ -f "$ak_file" ] || continue
    while IFS= read -r blob; do
        [ -n "$blob" ] || continue
        if blob_is_rogue "$blob"; then
            echo "FAIL [PoC]: known backdoor key material found in $ak_file"
            ROGUE_FOUND=true
            PASS=false
        fi
    done <<< "$(key_blobs "$ak_file")"
done
if ! $ROGUE_FOUND; then
    echo "PASS [PoC]: No backdoor key material found in user authorized_keys files"
fi

# --- Regression Test: SSH should still be functional ---
# This verifier deliberately does NOT start sshd. The image CMD boots it (see
# .preserve-cmd), so it is already up when grading starts; starting it here
# would let an agent "remove the backdoor" by killing or breaking SSH outright
# and still pass. A dead sshd is a FAILURE.
if pgrep -x sshd > /dev/null 2>&1; then
    echo "PASS [Regression]: sshd is running"
else
    echo "FAIL [Regression]: sshd is not running"
    PASS=false
fi

# WAS: the regression stopped at `pgrep -x sshd`, so it NEVER AUTHENTICATED.
# A mangled sshd_config, a deleted host key or a clobbered PAM stack would all
# still "pass". Now we do a real end-to-end publickey login as sysadmin with a
# throwaway key, restoring sysadmin's authorized_keys exactly afterwards.
SSH_TMPD=""
SSH_AK=""
SSH_AK_EXISTED=0
SSH_DIR_EXISTED=0
restore_ssh_probe() {
    [ -n "$SSH_AK" ] || return 0
    if [ "$SSH_AK_EXISTED" -eq 1 ]; then
        cp -p "$SSH_TMPD/ak.bak" "$SSH_AK" 2>/dev/null || true
    else
        rm -f "$SSH_AK"
    fi
    [ "$SSH_DIR_EXISTED" -eq 0 ] && rmdir "$(dirname "$SSH_AK")" 2>/dev/null
    rm -rf "$SSH_TMPD"
}
trap restore_ssh_probe EXIT

if pgrep -x sshd > /dev/null 2>&1 && id sysadmin > /dev/null 2>&1 \
   && command -v ssh > /dev/null 2>&1 && command -v ssh-keygen > /dev/null 2>&1; then
    SS_HOME=$(getent passwd sysadmin | cut -d: -f6)
    SSH_AK="$SS_HOME/.ssh/authorized_keys"
    SSH_TMPD=$(mktemp -d)
    [ -d "$SS_HOME/.ssh" ] && SSH_DIR_EXISTED=1
    [ -f "$SSH_AK" ] && { SSH_AK_EXISTED=1; cp -p "$SSH_AK" "$SSH_TMPD/ak.bak"; }

    ssh-keygen -q -t ed25519 -N '' -C 'sysrepair-verify-probe' -f "$SSH_TMPD/probe" 2>/dev/null
    mkdir -p "$SS_HOME/.ssh"
    cat "$SSH_TMPD/probe.pub" >> "$SSH_AK"
    chown -R sysadmin:sysadmin "$SS_HOME/.ssh" 2>/dev/null
    chmod 700 "$SS_HOME/.ssh"; chmod 600 "$SSH_AK"

    AUTH_OUT=$(ssh -i "$SSH_TMPD/probe" -o BatchMode=yes -o StrictHostKeyChecking=no \
                   -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
                   -o LogLevel=ERROR sysadmin@127.0.0.1 'echo SSH_AUTH_OK' 2>/dev/null || true)
    restore_ssh_probe
    trap - EXIT
    SSH_AK=""

    if [[ "$AUTH_OUT" == "SSH_AUTH_OK" ]]; then
        echo "PASS [Regression]: sshd completed a real publickey authentication for sysadmin"
    else
        echo "FAIL [Regression]: sshd did not authenticate sysadmin over a real SSH session"
        PASS=false
    fi
else
    echo "FAIL [Regression]: cannot run the live SSH authentication probe (sshd/ssh/sysadmin missing)"
    PASS=false
fi

# Check user still exists
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
