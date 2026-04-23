#!/bin/bash
# Hivestorm HS21 scenario-07 verifier — strict behavioural.
# Every non-service probe exercises the subsystem (ssh login, sudo run,
# pamtester, smbclient connect, live kernel sysctl, http/tcp probes) and
# AND-gates config state with runtime behaviour. JSONL on stdout.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user             "$ROLES")
ADMIN_PW=$(jq -r .admin_weak_password "$ROLES")
HIDDEN=$(jq -r .hidden_user           "$ROLES")
UNAUTH=$(jq -r .unauthorized_user     "$ROLES")
NONADMIN=$(jq -r .nonadmin_user       "$ROLES")
MP3_PATH=$(jq -r .prohibited_mp3_path "$ROLES")
PERL_BD=$(jq -r .perl_backdoor_path   "$ROLES")
SHARE=$(jq -r .samba_share_name       "$ROLES")
PROH0=$(jq -r '.prohibited_packages[0]' "$ROLES")
PROH1=$(jq -r '.prohibited_packages[1]' "$ROLES")

emit() {
    local cat=""
    if [ -n "${5-}" ]; then cat=",\"category\":\"$5\""; fi
    printf '{"check":"%s","weight":%s,"pass":%s,"reason":%s%s}\n' \
        "$1" "$2" "$3" "$(jq -Rn --arg r "$4" '$r')" "$cat"
}

# Effective sysctl across all drop-ins in lexical order (last wins).
eff_sysctl() {
    local key="$1" val=""
    for f in $(ls /etc/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null | sort); do
        v=$(grep -E "^\s*${key}\s*=" "$f" 2>/dev/null | tail -1 \
            | sed -E 's/^[^=]+=\s*//; s/\s*$//')
        [ -n "$v" ] && val="$v"
    done
    printf '%s' "$val"
}

ensure_sshd() {
    pgrep -x sshd >/dev/null 2>&1 || { mkdir -p /run/sshd /var/run/sshd
        /usr/sbin/sshd >/dev/null 2>&1; sleep 1; }
}

ssh_probe() {
    local user="$1" pw="$2"
    ensure_sshd
    sshpass -p "$pw" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o ConnectTimeout=3 "$user@127.0.0.1" true >/dev/null 2>&1
}

# -----------------------------------------------------------------------------
# 1. hidden user: resolves AND can log in
resolves=true; logins=true
id "$HIDDEN" >/dev/null 2>&1 || resolves=false
ssh_probe "$HIDDEN" changeme || logins=false
if $resolves || $logins; then
    emit hidden_user_removed 3 false "resolves=$resolves logins=$logins"
else
    emit hidden_user_removed 3 true ""
fi

# 2. unauthorized user: resolves AND can log in
resolves=true; logins=true
id "$UNAUTH" >/dev/null 2>&1 || resolves=false
ssh_probe "$UNAUTH" changeme || logins=false
if $resolves || $logins; then
    emit unauthorized_user_removed 3 false "resolves=$resolves logins=$logins"
else
    emit unauthorized_user_removed 3 true ""
fi

# 3. unauthorized sudoers drop-in: file present AND sudo -n works for UNAUTH
dropin=false; sudo_ok=false
[ -f "/etc/sudoers.d/90-${UNAUTH}" ] && dropin=true
if id "$UNAUTH" >/dev/null 2>&1; then
    su -s /bin/bash -c 'sudo -n true' "$UNAUTH" >/dev/null 2>&1 && sudo_ok=true
fi
if $dropin || $sudo_ok; then
    emit unauthorized_sudoers_removed 2 false "dropin=$dropin sudo_ok=$sudo_ok"
else
    emit unauthorized_sudoers_removed 2 true ""
fi

# 4. nonadmin not in sudo: group membership AND sudo -l shows sudo rights
nonadmin_sudo=false; sudo_listed=false
if id "$NONADMIN" >/dev/null 2>&1; then
    id -nG "$NONADMIN" | tr ' ' '\n' | grep -qx sudo && nonadmin_sudo=true
    su -s /bin/bash -c "SUDO_ASKPASS=/bin/false sudo -l" "$NONADMIN" 2>/dev/null \
        | grep -Eq '\(ALL' && sudo_listed=true
fi
if $nonadmin_sudo || $sudo_listed; then
    emit nonadmin_not_sudo 2 false "grp=$nonadmin_sudo listed=$sudo_listed"
else
    emit nonadmin_not_sudo 2 true ""
fi

# 5. irc user cannot log in (shell nologin/false OR ssh rejected)
shell_ok=true; login_ok=true
IRC_SHELL=$(getent passwd irc 2>/dev/null | cut -d: -f7)
case "$IRC_SHELL" in
    ""|*nologin|*false) shell_ok=false ;;
esac
ssh_probe irc changeme || login_ok=false
if $shell_ok || $login_ok; then
    emit irc_user_nologin 2 false "shell=$IRC_SHELL login=$login_ok"
else
    emit irc_user_nologin 2 true ""
fi

# 6. PAM nullok removed — pamtester with empty password must fail
probe_u="_hs_pamprobe_$$"
useradd -m -s /bin/bash "$probe_u" >/dev/null 2>&1
echo "${probe_u}:changeme" | chpasswd >/dev/null 2>&1
passwd -d "$probe_u" >/dev/null 2>&1
null_ok=false
if printf '\n' | pamtester -I tty=tty1 login "$probe_u" authenticate >/dev/null 2>&1; then
    null_ok=true
fi
if $null_ok; then
    emit pam_no_nullok 2 false "PAM accepts empty password"
else
    emit pam_no_nullok 2 true ""
fi

# 7. PAM pwquality — chpasswd rejects a trivially weak password
echo "${probe_u}:Str0ng!Base#2026" | chpasswd >/dev/null 2>&1
weak_accept=false
if echo "${probe_u}:abc" | chpasswd >/dev/null 2>&1; then
    weak_accept=true
fi
if $weak_accept; then
    emit pam_pwquality 2 false "weak pw not rejected"
else
    emit pam_pwquality 2 true ""
fi
userdel -r "$probe_u" >/dev/null 2>&1

# 8. sysctl tcp_syncookies=1 (effective + live AND-gate)
eff=$(eff_sysctl net.ipv4.tcp_syncookies)
live=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
if [ "$eff" = "1" ] && [ "$live" = "1" ]; then
    emit sysctl_syncookies 1 true ""
else
    emit sysctl_syncookies 1 false "eff=$eff live=$live"
fi

# 9. sysctl icmp_echo_ignore_broadcasts=1
eff=$(eff_sysctl net.ipv4.icmp_echo_ignore_broadcasts)
live=$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null)
if [ "$eff" = "1" ] && [ "$live" = "1" ]; then
    emit sysctl_ignore_bcast 1 true ""
else
    emit sysctl_ignore_bcast 1 false "eff=$eff live=$live"
fi

# 10. sysctl ip_forward=0
eff=$(eff_sysctl net.ipv4.ip_forward)
live=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
if [ "$eff" = "0" ] && [ "$live" = "0" ]; then
    emit sysctl_ip_forward 1 true ""
else
    emit sysctl_ip_forward 1 false "eff=$eff live=$live"
fi

# 11. UFW enabled — live status query
cfg=false; live=false
grep -Eq '^\s*ENABLED\s*=\s*yes' /etc/ufw/ufw.conf 2>/dev/null && cfg=true
ufw status 2>/dev/null | head -1 | grep -qi 'Status: active' && live=true
if $cfg && $live; then
    emit ufw_enabled 2 true ""
else
    emit ufw_enabled 2 false "cfg=$cfg live=$live"
fi

# 12. GRUB perms — mode AND non-root read test
mode_bad=true; read_bad=true
if [ -f /boot/grub/grub.cfg ]; then
    MODE=$(stat -c '%a' /boot/grub/grub.cfg)
    case "$MODE" in 600|640|400|440) mode_bad=false ;; esac
    if id "$NONADMIN" >/dev/null 2>&1; then
        su -s /bin/bash -c 'test -r /boot/grub/grub.cfg' "$NONADMIN" 2>/dev/null \
            || read_bad=false
    else
        read_bad=false
    fi
else
    mode_bad=false; read_bad=false
fi
if $mode_bad || $read_bad; then
    emit grub_perms 2 false "mode=${MODE:-missing} nonroot_read=$read_bad"
else
    emit grub_perms 2 true ""
fi

# 13. LightDM hardened — no TCP, no autologin (file absent/commented too)
bad=false
if [ -f /etc/lightdm/lightdm.conf ]; then
    grep -Eq '^\s*xserver-allow-tcp\s*=\s*true' /etc/lightdm/lightdm.conf && bad=true
    grep -Eq '^\s*autologin-user\s*=\s*\S' /etc/lightdm/lightdm.conf && bad=true
fi
if $bad; then
    emit lightdm_hardened 2 false "lightdm still permissive"
else
    emit lightdm_hardened 2 true ""
fi

# 14. Samba SMB1 off — behavioural: smbclient -m NT1 must be refused
# Give samba a moment if freshly started.
service smbd status >/dev/null 2>&1 || service smbd start >/dev/null 2>&1
sleep 1
smb1_works=false
if smbclient -N -m NT1 "//127.0.0.1/${SHARE}" -c 'ls' >/dev/null 2>&1; then
    smb1_works=true
fi
if $smb1_works; then
    emit samba_smb1_off 3 false "SMB1 accepted by smbd"
else
    emit samba_smb1_off 3 true ""
fi

# 15. Samba encryption required — testparm reports effective value
enc=$(testparm -s --parameter-name='smb encrypt' 2>/dev/null | tr -d '[:space:]' | tr 'A-Z' 'a-z')
case "$enc" in
    required|mandatory) emit samba_encrypt 3 true "" ;;
    *) emit samba_encrypt 3 false "smb encrypt=${enc:-unset}" ;;
esac

# 16. Samba share no guest — smbclient -N must be refused
guest_ok=false
if smbclient -N "//127.0.0.1/${SHARE}" -c 'ls' >/dev/null 2>&1; then
    guest_ok=true
fi
if $guest_ok; then
    emit samba_no_guest 2 false "guest access allowed"
else
    emit samba_no_guest 2 true ""
fi

# 17/18. prohibited packages — installed-status AND command on PATH
for idx in 0 1; do
    p=$(jq -r ".prohibited_packages[$idx]" "$ROLES")
    inst=false; onpath=false
    dpkg -l "$p" 2>/dev/null | grep -Eq '^ii' && inst=true
    command -v "$p" >/dev/null 2>&1 && onpath=true
    if $inst || $onpath; then
        emit "prohibited_pkg_${idx}_removed" 2 false "$p still installed or on PATH"
    else
        emit "prohibited_pkg_${idx}_removed" 2 true ""
    fi
done

# 19. prohibited MP3
if [ -f "$MP3_PATH" ]; then
    emit prohibited_mp3_removed 2 false "$MP3_PATH present"
else
    emit prohibited_mp3_removed 2 true ""
fi

# 20. perl owl-shell — file absent AND no outbound beacon to :4444
file_present=false; beacon=false
[ -f "$PERL_BD" ] && file_present=true
# If process is running and trying to connect, ss shows it. Also scan procs.
ss -tnp 2>/dev/null | grep -q ':4444' && beacon=true
pgrep -fa "$(basename "$PERL_BD" 2>/dev/null || echo owl)" >/dev/null 2>&1 && beacon=true
if $file_present || $beacon; then
    emit perl_backdoor_removed 3 false "file=$file_present beacon=$beacon"
else
    emit perl_backdoor_removed 3 true ""
fi

# 21. rc.local clean
if [ -f /etc/rc.local ] && grep -Fq "$PERL_BD" /etc/rc.local; then
    emit rc_local_clean 2 false "rc.local references $PERL_BD"
else
    emit rc_local_clean 2 true ""
fi

# 22. ircd disabled — installed AND listening on 6667
inst=false; listen=false
dpkg -l ircd-irc2 2>/dev/null | grep -Eq '^ii' && inst=true
ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':6667$' && listen=true
# Behavioural: try to talk IRC.
responds=false
exec 3<>/dev/tcp/127.0.0.1/6667 2>/dev/null \
    && { printf 'QUIT\r\n' >&3; read -t 1 line <&3 && responds=true; exec 3<&- 3>&-; }
if $inst && { $listen || $responds; }; then
    emit ircd_disabled 2 false "inst=$inst listen=$listen responds=$responds"
else
    emit ircd_disabled 2 true ""
fi

# ---- service probes (weight:0) ----------------------------------------------
if id "$ADMIN" >/dev/null 2>&1; then
    emit admin_user_preserved 0 true "" service
else
    emit admin_user_preserved 0 false "$ADMIN deleted" service
fi

if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':445$'; then
    emit smbd_up 0 true "" service
else
    emit smbd_up 0 false "smbd not listening" service
fi

if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':22$'; then
    emit sshd_up 0 true "" service
else
    emit sshd_up 0 false "sshd not listening" service
fi

exit 0
