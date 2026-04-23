#!/bin/bash
# Hivestorm HS20 scenario-02 verifier — strict behavioural + config.
# Every non-service check exercises the subsystem. Baseline = all pass:false.
# JSONL on stdout. Never short-circuits.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user             "$ROLES")
ADMIN_PW=$(jq -r .admin_weak_password "$ROLES")
BACKDOOR=$(jq -r .backdoor_user       "$ROLES")
TROJAN=$(jq -r .trojan_path           "$ROLES")
SUID_PLANT=$(jq -r .suid_plant        "$ROLES")
CRON_PATH=$(jq -r .cron_path          "$ROLES")
PORT=$(jq -r .listener_port           "$ROLES")
POISONED=$(jq -r .poisoned_host       "$ROLES")
ROGUE_KEY=$(jq -r .rogue_authorized_key "$ROLES")
SHARE=$(jq -r .samba_share_name       "$ROLES")

emit() {
    local cat=""
    if [ -n "${5-}" ]; then cat=",\"category\":\"$5\""; fi
    printf '{"check":"%s","weight":%s,"pass":%s,"reason":%s%s}\n' \
        "$1" "$2" "$3" "$(jq -Rn --arg r "$4" '$r')" "$cat"
}

eff_sysctl() {
    local key="$1" files
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
    local u="$1" pw="$2"
    sshpass -p "$pw" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 -o ConnectTimeout=4 -o LogLevel=ERROR \
        "$u@127.0.0.1" true 2>/dev/null
}

# ---- 1. backdoor user removed -----------------------------------------------
bd_resolves=false; bd_logins=false
getent passwd "$BACKDOOR" >/dev/null 2>&1 && bd_resolves=true
ssh_probe "$BACKDOOR" "changeme" && bd_logins=true
if $bd_resolves || $bd_logins; then
    emit backdoor_user_removed 3 false "resolves=$bd_resolves logins=$bd_logins"
else
    emit backdoor_user_removed 3 true ""
fi

# ---- 2. backdoor sudoers dropin removed + sudo -n denied --------------------
sud_file=false; sud_bad=false
[ -f "/etc/sudoers.d/90-${BACKDOOR}" ] && sud_file=true
if id "$BACKDOOR" >/dev/null 2>&1; then
    su -s /bin/bash -c 'sudo -n /bin/true' "$BACKDOOR" >/dev/null 2>&1 && sud_bad=true
fi
if ! $sud_file && ! $sud_bad; then
    emit backdoor_sudoers_removed 2 true ""
else
    emit backdoor_sudoers_removed 2 false "dropin=$sud_file sudo_ok=$sud_bad"
fi

# ---- 3. sudo-group NOPASSWD removed (config + behaviour as admin) -----------
dropin99=false; admin_nopw=false
[ -f /etc/sudoers.d/99-sudo-nopw ] && dropin99=true
grep -REq '^\s*%sudo\s+.*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null && dropin99=true
if id "$ADMIN" >/dev/null 2>&1; then
    su -s /bin/bash -c 'sudo -n /bin/true' "$ADMIN" >/dev/null 2>&1 && admin_nopw=true
fi
if ! $dropin99 && ! $admin_nopw; then
    emit sudo_group_nopw_removed 2 true ""
else
    emit sudo_group_nopw_removed 2 false "dropin=$dropin99 admin_nopw=$admin_nopw"
fi

# ---- 4. rogue authorized_keys cleaned (file content) ------------------------
AUTH_FILE="$(getent passwd "$ADMIN" | cut -d: -f6)/.ssh/authorized_keys"
if [ -f "$AUTH_FILE" ] && grep -Fq "$ROGUE_KEY" "$AUTH_FILE"; then
    emit rogue_authkey_removed 3 false "rogue pubkey present in $AUTH_FILE"
else
    emit rogue_authkey_removed 3 true ""
fi

# ---- 5. /etc/hosts not poisoned (behavioural via getent) --------------------
resolved=$(getent hosts "$POISONED" 2>/dev/null | awk '{print $1;exit}')
if [ "$resolved" = "10.13.37.66" ]; then
    emit hosts_not_poisoned 2 false "$POISONED -> 10.13.37.66"
else
    # also scan file to catch cases where NSS short-circuits
    if grep -Eq "^\s*10\.13\.37\.66\s+.*\b${POISONED}\b" /etc/hosts 2>/dev/null; then
        emit hosts_not_poisoned 2 false "poison entry still in /etc/hosts"
    else
        emit hosts_not_poisoned 2 true ""
    fi
fi

# ---- 6. rogue cron removed --------------------------------------------------
cron_file=false; cron_beacon=false
[ -e "$CRON_PATH" ] && cron_file=true
if grep -R -l "10\.0\.0\.2" /etc/cron.d /etc/crontab /etc/cron.hourly \
      /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
      /var/spool/cron 2>/dev/null | grep -q .; then
    cron_beacon=true
fi
if ! $cron_file && ! $cron_beacon; then
    emit rogue_cron_removed 3 true ""
else
    emit rogue_cron_removed 3 false "file=$cron_file beacon=$cron_beacon"
fi

# ---- 7. trojan no longer behaves as netcat ----------------------------------
trojan_is_nc=false
if [ -f "$TROJAN" ]; then
    for ref in /bin/nc.traditional /bin/nc.openbsd; do
        [ -f "$ref" ] && cmp -s "$TROJAN" "$ref" && trojan_is_nc=true
    done
    if "$TROJAN" -h 2>&1 | grep -Eqi '\[-?hklnrtuvz\]|cmd line:|nc -h for help'; then
        trojan_is_nc=true
    fi
fi
if $trojan_is_nc; then
    emit trojan_removed 3 false "$TROJAN still behaves as netcat"
else
    emit trojan_removed 3 true ""
fi

# ---- 8. SUID plant cannot grant root ----------------------------------------
suid_bad=false
if [ -f "$SUID_PLANT" ]; then
    [ -u "$SUID_PLANT" ] && suid_bad=true
    if id "$ADMIN" >/dev/null 2>&1; then
        euid=$(su -s /bin/bash -c "\"$SUID_PLANT\" -p -c 'id -u'" "$ADMIN" 2>/dev/null | tr -d '[:space:]')
        [ "$euid" = "0" ] && suid_bad=true
    fi
fi
if $suid_bad; then
    emit suid_plant_fixed 3 false "$SUID_PLANT still privileged"
else
    emit suid_plant_fixed 3 true ""
fi

# ---- 9. backdoor listener silent --------------------------------------------
listener_open=false
ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ":${PORT}\$" && listener_open=true
if (exec 3<>/dev/tcp/127.0.0.1/${PORT}) 2>/dev/null; then
    listener_open=true
    exec 3<&- 3>&- 2>/dev/null
fi
if $listener_open; then
    emit backdoor_listener_silent 3 false "port $PORT reachable"
else
    emit backdoor_listener_silent 3 true ""
fi

# ---- 10. PAM pwquality rejects weak pw (behavioural passwd) ----------------
probe_u="hsprobe$$"
userdel -r "$probe_u" >/dev/null 2>&1
useradd -m -s /bin/bash "$probe_u" >/dev/null 2>&1
echo "${probe_u}:initPW_xyz9!" | chpasswd 2>/dev/null
# Run passwd as the probe user (non-root triggers PAM enforcement).
out=$(su -s /bin/bash -c "printf '%s\n%s\n%s\n' 'initPW_xyz9!' 'abc' 'abc' | passwd" "$probe_u" 2>&1)
ec=$?
userdel -r "$probe_u" >/dev/null 2>&1
if echo "$out" | grep -Eqi 'BAD PASSWORD|too short|simpler|dictionary|failed preliminary' && [ $ec -ne 0 ]; then
    emit pam_pwquality 2 true ""
else
    emit pam_pwquality 2 false "weak pw accepted or not rejected by pwquality"
fi

# ---- 11. sysctl dmesg_restrict = 1 (eff + live) ----------------------------
e=$(eff_sysctl kernel.dmesg_restrict)
l=$(sysctl -n kernel.dmesg_restrict 2>/dev/null)
if [ "$e" = "1" ] && [ "$l" = "1" ]; then
    emit sysctl_dmesg_restrict 1 true ""
else
    emit sysctl_dmesg_restrict 1 false "eff=$e live=$l"
fi

# ---- 12. sysctl kptr_restrict >= 1 (eff + live) ----------------------------
e=$(eff_sysctl kernel.kptr_restrict)
l=$(sysctl -n kernel.kptr_restrict 2>/dev/null)
ok=false
if [ -n "$e" ] && [ "$e" -ge 1 ] 2>/dev/null && [ -n "$l" ] && [ "$l" -ge 1 ] 2>/dev/null; then
    ok=true
fi
if $ok; then
    emit sysctl_kptr_restrict 1 true ""
else
    emit sysctl_kptr_restrict 1 false "eff=$e live=$l"
fi

# ---- 13. sshd PermitRootLogin no (effective + root ssh fails) --------------
eff_prl=$(sshd_eff permitrootlogin)
root_blocked=true
ssh_probe root toor && root_blocked=false
ssh_probe root root && root_blocked=false
prl_ok=false
case "$eff_prl" in no|prohibit-password) prl_ok=true ;; esac
if $prl_ok && $root_blocked; then
    emit sshd_no_root 2 true ""
else
    emit sshd_no_root 2 false "PermitRootLogin=$eff_prl root_blocked=$root_blocked"
fi

# ---- 14. samba share not guest-accessible (smbclient -N) -------------------
# Ensure smbd is running so we can actually probe it.
service smbd start >/dev/null 2>&1
service nmbd start >/dev/null 2>&1
sleep 1
guest_ls=false
if smbclient "//127.0.0.1/${SHARE}" -N -c 'ls' >/dev/null 2>&1; then
    guest_ls=true
fi
# Fallback: even without listing, share advertised as guest=yes in active config.
cfg_guest=false
if testparm -s --parameter-name='guest ok' --section-name="${SHARE}" 2>/dev/null | grep -iq '^\s*yes'; then
    cfg_guest=true
fi
if ! $guest_ls && ! $cfg_guest; then
    emit samba_no_guest 2 true ""
else
    emit samba_no_guest 2 false "guest_ls=$guest_ls cfg_guest=$cfg_guest"
fi

# ---- 15. telnetd not installed / not listening ------------------------------
telnet_installed=false; telnet_listening=false
dpkg -l telnetd 2>/dev/null | grep -Eq '^ii' && telnet_installed=true
ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':23$' && telnet_listening=true
# Behavioural: try to connect with telnet client
if (exec 3<>/dev/tcp/127.0.0.1/23) 2>/dev/null; then
    telnet_listening=true
    exec 3<&- 3>&- 2>/dev/null
fi
if ! $telnet_installed && ! $telnet_listening; then
    emit telnetd_removed 1 true ""
else
    emit telnetd_removed 1 false "installed=$telnet_installed listening=$telnet_listening"
fi

# ---- 16. vsftpd anonymous disabled / or package removed --------------------
service vsftpd start >/dev/null 2>&1
sleep 1
anon_ok=false
# Try anonymous ftp LIST via curl.
if curl -sS --max-time 5 -u 'anonymous:x@x' ftp://127.0.0.1/ -o /dev/null 2>/dev/null; then
    anon_ok=true
fi
pkg_installed=false
dpkg -l vsftpd 2>/dev/null | grep -Eq '^ii' && pkg_installed=true
if ! $anon_ok; then
    emit vsftpd_no_anon 2 true ""
else
    emit vsftpd_no_anon 2 false "anon ftp LIST succeeded (pkg=$pkg_installed)"
fi

# ---- service probes ---------------------------------------------------------
if id "$ADMIN" >/dev/null 2>&1; then
    emit admin_user_preserved 0 true "" service
else
    emit admin_user_preserved 0 false "$ADMIN deleted" service
fi
if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':22$'; then
    emit ssh_up 0 true "" service
else
    emit ssh_up 0 false "sshd not listening" service
fi
if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':445$'; then
    emit smbd_up 0 true "" service
else
    emit smbd_up 0 false "smbd not listening" service
fi

exit 0
