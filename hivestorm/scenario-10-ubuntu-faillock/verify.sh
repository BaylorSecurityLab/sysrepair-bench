#!/bin/bash
# Hivestorm HS23 scenario-10 verifier — JSONL on stdout.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user             "$ROLES")
HIDDEN=$(jq -r .hidden_user           "$ROLES")
NONADMIN=$(jq -r .nonadmin_user       "$ROLES")
PROH_PKG=$(jq -r .prohibited_package  "$ROLES")
MP3_PATH=$(jq -r .prohibited_mp3_path "$ROLES")
mapfile -t REMOTE_USERS < <(jq -r '.remote_group_users[]' "$ROLES")

emit() {
    local cat=""
    if [ -n "${5-}" ]; then cat=",\"category\":\"$5\""; fi
    printf '{"check":"%s","weight":%s,"pass":%s,"reason":%s%s}\n' \
        "$1" "$2" "$3" "$(jq -Rn --arg r "$4" '$r')" "$cat"
}

# 1. hidden user removed
if id "$HIDDEN" >/dev/null 2>&1; then
    emit hidden_user_removed 3 false "$HIDDEN exists"
else
    emit hidden_user_removed 3 true ""
fi

# 2. nonadmin not in sudo
if id "$NONADMIN" >/dev/null 2>&1 && id -nG "$NONADMIN" | tr ' ' '\n' | grep -qx sudo; then
    emit nonadmin_not_sudo 2 false "$NONADMIN in sudo"
else
    emit nonadmin_not_sudo 2 true ""
fi

# 3. PAM faillock with authfail
if grep -Eq 'pam_faillock\.so.*authfail' /etc/pam.d/common-auth 2>/dev/null; then
    emit pam_faillock_authfail 2 true ""
else
    emit pam_faillock_authfail 2 false "pam_faillock authfail missing"
fi

# 4. PAM pam_unix uses sha512 or yescrypt
if grep -Eq 'pam_unix\.so.*\bmd5\b' /etc/pam.d/common-password 2>/dev/null; then
    emit pam_unix_strong_hash 2 false "md5 still set"
else
    emit pam_unix_strong_hash 2 true ""
fi

# 5. SSH PubkeyAuthentication yes
if grep -Eqi '^\s*PubkeyAuthentication\s+yes' /etc/ssh/sshd_config 2>/dev/null; then
    emit ssh_pubkey_yes 2 true ""
else
    emit ssh_pubkey_yes 2 false "PubkeyAuthentication not yes"
fi

# 6. SSH PermitRootLogin no
if grep -Eqi '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config 2>/dev/null; then
    emit ssh_no_root 2 true ""
else
    emit ssh_no_root 2 false "PermitRootLogin not no"
fi

# 7. UFW enabled
if grep -Eq '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null \
   || ufw status 2>/dev/null | grep -qi 'Status: active'; then
    emit ufw_enabled 2 true ""
else
    emit ufw_enabled 2 false "ufw still disabled"
fi

# 8. sysctl tcp_syncookies = 1
if [ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" = "1" ]; then
    emit sysctl_syncookies 1 true ""
else
    emit sysctl_syncookies 1 false "tcp_syncookies off"
fi

# 9. prohibited package removed
if dpkg -l "$PROH_PKG" 2>/dev/null | grep -Eq '^ii'; then
    emit prohibited_package_removed 2 false "$PROH_PKG installed"
else
    emit prohibited_package_removed 2 true ""
fi

# 10. exact `remote` group membership
if getent group remote >/dev/null 2>&1; then
    ACTUAL=$(getent group remote | awk -F: '{print $4}' | tr ',' '\n' | sort -u | grep -v '^$' | xargs)
    EXPECTED=$(printf '%s\n' "${REMOTE_USERS[@]}" | sort -u | xargs)
    if [ "$ACTUAL" = "$EXPECTED" ]; then
        emit remote_group_exact 2 true ""
    else
        emit remote_group_exact 2 false "remote=[$ACTUAL] expected=[$EXPECTED]"
    fi
else
    emit remote_group_exact 2 false "remote group missing"
fi

# 11. prohibited mp3 removed
if [ -f "$MP3_PATH" ]; then
    emit prohibited_mp3_removed 2 false "$MP3_PATH present"
else
    emit prohibited_mp3_removed 2 true ""
fi

# ---- service probes ----------------------------------------------------------
if id "$ADMIN" >/dev/null 2>&1; then
    emit admin_user_preserved 0 true "" service
else
    emit admin_user_preserved 0 false "$ADMIN deleted" service
fi

if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':22$'; then
    emit sshd_up 0 true "" service
else
    emit sshd_up 0 false "sshd not listening on :22" service
fi

exit 0
