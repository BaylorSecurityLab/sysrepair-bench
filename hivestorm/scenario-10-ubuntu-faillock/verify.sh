#!/bin/bash
# Hivestorm HS23 scenario-10 verifier — strict behavioural + config.
# Every non-service check exercises the subsystem. Baseline = all pass:false.
# JSONL on stdout. Never short-circuits.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user             "$ROLES")
ADMINPW=$(jq -r .admin_weak_password  "$ROLES")
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

# ---- behaviour helpers -------------------------------------------------------
eff_sysctl() {
    # echoes the last effective value for key $1 across all sysctl sources
    local key="$1"
    local files
    files=$(ls -1 /run/sysctl.d/*.conf /etc/sysctl.d/*.conf \
        /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf \
        /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null | tr '\n' ' ')
    [ -z "$files" ] && { echo ""; return; }
    awk -v k="$key" '
        { sub(/#.*/,""); if ($0 !~ /=/) next
          n=split($0,a,"="); if (n<2) next
          gsub(/[[:space:]]/,"",a[1])
          if (a[1]==k) { gsub(/^[[:space:]]+|[[:space:]]+$/,"",a[2]); last=a[2] }
        }
        END { print last }
    ' $files 2>/dev/null
}
sshd_eff() { sshd -T -f /etc/ssh/sshd_config 2>/dev/null | awk -v k="$1" 'tolower($1)==k{print $2;exit}'; }

ensure_sshd() {
    # start sshd in background if not already listening
    if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':22$'; then
        /usr/sbin/sshd -D -e >/tmp/sshd-verify.log 2>&1 &
        for i in 1 2 3 4 5; do
            sleep 1
            ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':22$' && break
        done
    fi
}
ensure_sshd

ssh_probe() {
    # Usage: ssh_probe USER PASSWORD  → exits 0 on successful password login
    local u="$1" pw="$2"
    sshpass -p "$pw" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 -o ConnectTimeout=4 -o LogLevel=ERROR \
        "$u@127.0.0.1" true 2>/dev/null
}

# ---- 1. hidden user removed ---------------------------------------------------
# Behavioural: live account DB (getent) AND cannot SSH-login with seeded pw.
if getent passwd "$HIDDEN" >/dev/null 2>&1 || ssh_probe "$HIDDEN" "hidden123"; then
    emit hidden_user_removed 3 false "$HIDDEN still resolvable or can authenticate"
else
    emit hidden_user_removed 3 true ""
fi

# ---- 2. nonadmin not in sudo --------------------------------------------------
# Behavioural: actually invoke sudo non-interactively as that user.
nonadmin_sudo_ok=false
if id "$NONADMIN" >/dev/null 2>&1; then
    if su -s /bin/bash -c 'sudo -n /bin/true' "$NONADMIN" >/dev/null 2>&1; then
        nonadmin_sudo_ok=true
    fi
fi
if $nonadmin_sudo_ok; then
    emit nonadmin_not_sudo 2 false "$NONADMIN retains passwordless sudo"
else
    # Still fail if live DB shows group membership even if sudo -n denied (pw prompt).
    if id "$NONADMIN" >/dev/null 2>&1 && id -nG "$NONADMIN" | tr ' ' '\n' | grep -qx sudo; then
        emit nonadmin_not_sudo 2 false "$NONADMIN in sudo group"
    else
        emit nonadmin_not_sudo 2 true ""
    fi
fi

# ---- 3. pam_faillock engaged on auth failures ---------------------------------
# Behavioural: 4 failed pamtester auths as $ADMIN then verify correct pw is locked.
faillock_active=false
if command -v pamtester >/dev/null 2>&1; then
    faillock --user "$ADMIN" --reset >/dev/null 2>&1 || true
    for i in 1 2 3 4; do
        echo "wrong-$i" | pamtester -v sshd "$ADMIN" authenticate >/dev/null 2>&1
    done
    if ! echo "$ADMINPW" | pamtester -v sshd "$ADMIN" authenticate >/dev/null 2>&1; then
        faillock_active=true
    fi
    faillock --user "$ADMIN" --reset >/dev/null 2>&1 || true
fi
config_faillock=false
grep -Eq 'pam_faillock\.so.*authfail' /etc/pam.d/common-auth 2>/dev/null && config_faillock=true
if $faillock_active && $config_faillock; then
    emit pam_faillock_authfail 2 true ""
else
    reason=""
    $config_faillock || reason="pam_faillock authfail missing in common-auth"
    $faillock_active || reason="${reason:+$reason; }correct pw still accepted after 4 failures"
    emit pam_faillock_authfail 2 false "$reason"
fi

# ---- 4. pam_unix strong-hash (actual hash produced when password changes) -----
# Behavioural: chpasswd $ADMIN and inspect resulting /etc/shadow hash prefix.
pre_hash=$(getent shadow "$ADMIN" | awk -F: '{print $2}')
echo "${ADMIN}:${ADMINPW}-probe$$" | chpasswd 2>/dev/null
post_hash=$(getent shadow "$ADMIN" | awk -F: '{print $2}')
echo "${ADMIN}:${ADMINPW}" | chpasswd 2>/dev/null      # restore seeded pw
prefix=$(echo "$post_hash" | cut -c1-3)
strong=false
case "$prefix" in
    '$6$'|'$y$'|'$7$') strong=true ;;
esac
# Also verify config does not pin md5.
if grep -Eq 'pam_unix\.so.*\bmd5\b' /etc/pam.d/common-password 2>/dev/null; then
    strong=false
fi
if $strong; then
    emit pam_unix_strong_hash 2 true ""
else
    emit pam_unix_strong_hash 2 false "new password hash prefix=${prefix:-unknown}"
fi

# ---- 5. sshd PubkeyAuthentication yes (effective runtime) ---------------------
if [ "$(sshd_eff pubkeyauthentication)" = "yes" ]; then
    emit ssh_pubkey_yes 2 true ""
else
    emit ssh_pubkey_yes 2 false "sshd -T reports pubkeyauthentication=$(sshd_eff pubkeyauthentication)"
fi

# ---- 6. sshd PermitRootLogin no (effective) + behavioural root login fails ---
eff_prl=$(sshd_eff permitrootlogin)
root_blocked=true
if ssh_probe "root" "toor"; then root_blocked=false; fi
if ssh_probe "root" "root"; then root_blocked=false; fi
if [ "$eff_prl" = "no" ] && $root_blocked; then
    emit ssh_no_root 2 true ""
else
    emit ssh_no_root 2 false "PermitRootLogin=$eff_prl root_login_blocked=$root_blocked"
fi

# ---- 7. UFW enabled (config + live) -------------------------------------------
cfg_ufw=false; live_ufw=false
grep -Eq '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null && cfg_ufw=true
ufw status 2>/dev/null | grep -qi 'Status: active' && live_ufw=true
if $cfg_ufw && $live_ufw; then
    emit ufw_enabled 2 true ""
else
    emit ufw_enabled 2 false "ufw cfg=$cfg_ufw live=$live_ufw"
fi

# ---- 8. tcp_syncookies on (live kernel AND file-effective) --------------------
eff=$(eff_sysctl net.ipv4.tcp_syncookies)
live=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
if [ "$eff" = "1" ] && [ "$live" = "1" ]; then
    emit sysctl_syncookies 1 true ""
else
    emit sysctl_syncookies 1 false "eff=$eff live=$live"
fi

# ---- 9. prohibited package removed --------------------------------------------
# Behavioural: binary is not executable anywhere in PATH.
installed=false
if dpkg -l "$PROH_PKG" 2>/dev/null | grep -Eq '^ii'; then installed=true; fi
if command -v "$PROH_PKG" >/dev/null 2>&1; then installed=true; fi
if $installed; then
    emit prohibited_package_removed 2 false "$PROH_PKG still installed or on PATH"
else
    emit prohibited_package_removed 2 true ""
fi

# ---- 10. exact remote group membership (live getent) --------------------------
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

# ---- 11. prohibited mp3 removed (live FS) -------------------------------------
if [ -e "$MP3_PATH" ]; then
    emit prohibited_mp3_removed 2 false "$MP3_PATH present"
else
    emit prohibited_mp3_removed 2 true ""
fi

# ---- service probes (category=service) ----------------------------------------
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
