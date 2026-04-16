#!/bin/bash
# Hivestorm HS20 scenario-02 verifier.
# JSONL on stdout. Never short-circuits.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user           "$ROLES")
BACKDOOR=$(jq -r .backdoor_user     "$ROLES")
TROJAN=$(jq -r .trojan_path         "$ROLES")
SUID_PLANT=$(jq -r .suid_plant      "$ROLES")
CRON_PATH=$(jq -r .cron_path        "$ROLES")
PORT=$(jq -r .listener_port         "$ROLES")
POISONED=$(jq -r .poisoned_host     "$ROLES")
ROGUE_KEY=$(jq -r .rogue_authorized_key "$ROLES")
SHARE=$(jq -r .samba_share_name     "$ROLES")

emit() {
    local cat=""
    if [ -n "${5-}" ]; then cat=",\"category\":\"$5\""; fi
    printf '{"check":"%s","weight":%s,"pass":%s,"reason":%s%s}\n' \
        "$1" "$2" "$3" "$(jq -Rn --arg r "$4" '$r')" "$cat"
}

# 1. backdoor user removed
if id "$BACKDOOR" >/dev/null 2>&1; then
    emit backdoor_user_removed 3 false "$BACKDOOR exists"
else
    emit backdoor_user_removed 3 true ""
fi

# 2. backdoor sudoers drop-in removed
if [ -f "/etc/sudoers.d/90-${BACKDOOR}" ]; then
    emit backdoor_sudoers_removed 2 false "drop-in present"
else
    emit backdoor_sudoers_removed 2 true ""
fi

# 3. wheel/sudo NOPASSWD removed
if [ -f /etc/sudoers.d/99-sudo-nopw ] || grep -REq '^\s*%sudo\s+.*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
    emit sudo_group_nopw_removed 2 false "sudo group still NOPASSWD"
else
    emit sudo_group_nopw_removed 2 true ""
fi

# 4. rogue authorized_keys cleaned
AUTH_FILE="$(getent passwd "$ADMIN" | cut -d: -f6)/.ssh/authorized_keys"
if [ -f "$AUTH_FILE" ] && grep -Fq "$ROGUE_KEY" "$AUTH_FILE"; then
    emit rogue_authkey_removed 3 false "rogue key present"
else
    emit rogue_authkey_removed 3 true ""
fi

# 5. /etc/hosts not poisoned
if grep -Eq "[[:space:]]${POISONED}([[:space:]]|$)" /etc/hosts; then
    emit hosts_not_poisoned 2 false "$POISONED in /etc/hosts"
else
    emit hosts_not_poisoned 2 true ""
fi

# 6. rogue cron removed
if [ -e "$CRON_PATH" ]; then
    emit rogue_cron_removed 3 false "$CRON_PATH present"
else
    emit rogue_cron_removed 3 true ""
fi

# 7. trojan neutralized
NC_REAL=$(command -v nc.openbsd 2>/dev/null || command -v nc)
if [ -f "$TROJAN" ] && [ -n "$NC_REAL" ] && cmp -s "$TROJAN" "$NC_REAL" 2>/dev/null; then
    emit trojan_removed 3 false "$TROJAN matches netcat"
else
    emit trojan_removed 3 true ""
fi

# 8. SUID plant neutralized
if [ -f "$SUID_PLANT" ] && [ -u "$SUID_PLANT" ]; then
    emit suid_plant_fixed 3 false "$SUID_PLANT still SUID"
else
    emit suid_plant_fixed 3 true ""
fi

# 9. backdoor listener silent
if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ":${PORT}\$"; then
    emit backdoor_listener_silent 3 false "port $PORT listening"
else
    emit backdoor_listener_silent 3 true ""
fi

# 10. PAM pwquality / minlen configured
if grep -REq '(pam_pwquality|pam_cracklib).*minlen=([89]|1[0-9]+)' /etc/pam.d/ 2>/dev/null; then
    emit pam_pwquality 2 true ""
else
    emit pam_pwquality 2 false "no pam_pwquality minlen>=8"
fi

# 11. sysctl dmesg_restrict=1
if [ "$(sysctl -n kernel.dmesg_restrict 2>/dev/null)" = "1" ]; then
    emit sysctl_dmesg_restrict 1 true ""
else
    emit sysctl_dmesg_restrict 1 false "dmesg_restrict=0"
fi

# 12. sysctl kptr_restrict >=1
KPTR=$(sysctl -n kernel.kptr_restrict 2>/dev/null)
if [ -n "$KPTR" ] && [ "$KPTR" -ge 1 ] 2>/dev/null; then
    emit sysctl_kptr_restrict 1 true ""
else
    emit sysctl_kptr_restrict 1 false "kptr_restrict=${KPTR:-unset}"
fi

# 13. sshd PermitRootLogin no
if grep -Eq '^\s*PermitRootLogin\s+(no|prohibit-password)' /etc/ssh/sshd_config; then
    emit sshd_no_root 2 true ""
else
    emit sshd_no_root 2 false "PermitRootLogin not restricted"
fi

# 14. samba share not guest-writable
if grep -Pzoq "(?s)\[${SHARE}\].*?(guest ok\s*=\s*yes|public\s*=\s*yes)" /etc/samba/smb.conf 2>/dev/null; then
    emit samba_no_guest 2 false "share [${SHARE}] still guest-accessible"
else
    emit samba_no_guest 2 true ""
fi

# 15. telnetd not installed/enabled
if dpkg -l telnetd 2>/dev/null | grep -Eq '^ii'; then
    emit telnetd_removed 1 false "telnetd still installed"
else
    emit telnetd_removed 1 true ""
fi

# 16. vsftpd anon disabled (or package removed)
if dpkg -l vsftpd 2>/dev/null | grep -Eq '^ii'; then
    if grep -Eq '^\s*anonymous_enable\s*=\s*YES' /etc/vsftpd.conf 2>/dev/null; then
        emit vsftpd_no_anon 2 false "anonymous_enable=YES"
    else
        emit vsftpd_no_anon 2 true ""
    fi
else
    emit vsftpd_no_anon 2 true "vsftpd removed"
fi

# ---- service probes -----------------------------------------------------------
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
