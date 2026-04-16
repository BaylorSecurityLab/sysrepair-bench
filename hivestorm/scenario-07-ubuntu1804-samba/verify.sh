#!/bin/bash
# Hivestorm HS21 scenario-07 verifier. JSONL on stdout.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user             "$ROLES")
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

# 1. hidden user removed
if id "$HIDDEN" >/dev/null 2>&1; then
    emit hidden_user_removed 3 false "$HIDDEN exists"
else
    emit hidden_user_removed 3 true ""
fi

# 2. unauthorized user removed
if id "$UNAUTH" >/dev/null 2>&1; then
    emit unauthorized_user_removed 3 false "$UNAUTH exists"
else
    emit unauthorized_user_removed 3 true ""
fi

# 3. unauthorized sudoers drop-in removed
if [ -f "/etc/sudoers.d/90-${UNAUTH}" ]; then
    emit unauthorized_sudoers_removed 2 false ""
else
    emit unauthorized_sudoers_removed 2 true ""
fi

# 4. non-admin stripped from sudo
if id "$NONADMIN" >/dev/null 2>&1 && id -nG "$NONADMIN" | tr ' ' '\n' | grep -qx sudo; then
    emit nonadmin_not_sudo 2 false "$NONADMIN in sudo"
else
    emit nonadmin_not_sudo 2 true ""
fi

# 5. irc user has nologin shell
IRC_SHELL=$(getent passwd irc 2>/dev/null | cut -d: -f7)
case "$IRC_SHELL" in
    *nologin|*false)
        emit irc_user_nologin 2 true "" ;;
    "")
        emit irc_user_nologin 2 true "irc user removed" ;;
    *)
        emit irc_user_nologin 2 false "irc shell=$IRC_SHELL" ;;
esac

# 6. PAM null passwords disabled
if grep -Eq 'pam_unix\.so.*nullok' /etc/pam.d/common-auth 2>/dev/null; then
    emit pam_no_nullok 2 false "nullok set"
else
    emit pam_no_nullok 2 true ""
fi

# 7. PAM pwquality minlen
if grep -REq '(pam_pwquality|pam_cracklib).*minlen=([89]|1[0-9]+)' /etc/pam.d/ 2>/dev/null; then
    emit pam_pwquality 2 true ""
else
    emit pam_pwquality 2 false ""
fi

# 8. sysctl syncookies on
if [ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" = "1" ]; then
    emit sysctl_syncookies 1 true ""
else
    emit sysctl_syncookies 1 false "tcp_syncookies off"
fi

# 9. broadcast ICMP ignored
if [ "$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null)" = "1" ]; then
    emit sysctl_ignore_bcast 1 true ""
else
    emit sysctl_ignore_bcast 1 false ""
fi

# 10. ip_forward off
if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "0" ]; then
    emit sysctl_ip_forward 1 true ""
else
    emit sysctl_ip_forward 1 false "ip_forward on"
fi

# 11. UFW active
if ufw status 2>/dev/null | grep -qi 'Status: active'; then
    emit ufw_enabled 2 true ""
else
    emit ufw_enabled 2 false "ufw inactive"
fi

# 12. GRUB perms
if [ -f /boot/grub/grub.cfg ]; then
    MODE=$(stat -c '%a' /boot/grub/grub.cfg)
    case "$MODE" in
        600|640|400) emit grub_perms 2 true "" ;;
        *)           emit grub_perms 2 false "grub.cfg mode=$MODE" ;;
    esac
else
    emit grub_perms 2 true "grub.cfg removed"
fi

# 13. LightDM: no TCP, no autologin
if [ -f /etc/lightdm/lightdm.conf ]; then
    BAD=0
    grep -Eq '^\s*xserver-allow-tcp\s*=\s*true' /etc/lightdm/lightdm.conf && BAD=1
    grep -Eq '^\s*autologin-user\s*=' /etc/lightdm/lightdm.conf && BAD=1
    if [ "$BAD" = "0" ]; then
        emit lightdm_hardened 2 true ""
    else
        emit lightdm_hardened 2 false "lightdm still permissive"
    fi
else
    emit lightdm_hardened 2 true "lightdm.conf removed"
fi

# 14. Samba SMB1 disabled (min protocol >= SMB2)
if grep -REiq '^\s*min\s+protocol\s*=\s*(NT1|SMB1|CORE|LANMAN[0-9])' /etc/samba/ 2>/dev/null; then
    emit samba_smb1_off 3 false "min protocol still legacy"
else
    emit samba_smb1_off 3 true ""
fi

# 15. Samba encryption required
if grep -REiq '^\s*smb\s+encrypt\s*=\s*(required|mandatory)' /etc/samba/ 2>/dev/null; then
    emit samba_encrypt 3 true ""
else
    emit samba_encrypt 3 false "smb encrypt not required"
fi

# 16. Samba share no-guest
if grep -Pzoq "(?s)\[${SHARE}\].*?(guest ok\s*=\s*yes|public\s*=\s*yes)" /etc/samba/smb.conf 2>/dev/null; then
    emit samba_no_guest 2 false "share [${SHARE}] guest-accessible"
else
    emit samba_no_guest 2 true ""
fi

# 17. prohibited packages removed
for p in "$PROH0" "$PROH1"; do
    if dpkg -l "$p" 2>/dev/null | grep -Eq '^ii'; then
        emit "prohibited_${p}_removed" 2 false "$p installed"
    else
        emit "prohibited_${p}_removed" 2 true ""
    fi
done

# 18. prohibited MP3 removed
if [ -f "$MP3_PATH" ]; then
    emit prohibited_mp3_removed 2 false "$MP3_PATH present"
else
    emit prohibited_mp3_removed 2 true ""
fi

# 19. perl owl-shell removed
if [ -f "$PERL_BD" ]; then
    emit perl_backdoor_removed 3 false "$PERL_BD present"
else
    emit perl_backdoor_removed 3 true ""
fi

# 20. rc.local clean
if [ -f /etc/rc.local ] && grep -Fq "$PERL_BD" /etc/rc.local; then
    emit rc_local_clean 2 false "rc.local references $PERL_BD"
else
    emit rc_local_clean 2 true ""
fi

# 21. ircd removed or disabled
if dpkg -l ircd-irc2 2>/dev/null | grep -Eq '^ii'; then
    if pgrep -f ircd >/dev/null 2>&1; then
        emit ircd_disabled 2 false "ircd running"
    else
        emit ircd_disabled 2 true ""
    fi
else
    emit ircd_disabled 2 true "ircd removed"
fi

# ---- service probes ----------------------------------------------------------
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

exit 0
