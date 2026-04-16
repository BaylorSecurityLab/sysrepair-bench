#!/usr/bin/env bash
# Hivestorm scenario-12 verifier. JSONL on stdout. Never short-circuits.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user           "$ROLES")
BACKDOOR=$(jq -r .backdoor_user     "$ROLES")
EXTRA_UID0=$(jq -r .extra_uid0_user "$ROLES")
SUDOERS_DROP=$(jq -r .sudoers_drop_name "$ROLES")
ROGUE_REPO=$(jq -r .rogue_yum_repo_name "$ROLES")
TROJAN=$(jq -r .trojan_path         "$ROLES")
SUID_PLANT=$(jq -r .suid_plant      "$ROLES")
CRON_PATH=$(jq -r .cron_path        "$ROLES")
LISTENER_PORT=$(jq -r .listener_port "$ROLES")

emit() {
    local cat=""
    if [ -n "${5-}" ]; then cat=",\"category\":\"$5\""; fi
    printf '{"check":"%s","weight":%s,"pass":%s,"reason":%s%s}\n' \
        "$1" "$2" "$3" "$(jq -Rn --arg r "$4" '$r')" "$cat"
}

# 1. extra UID-0 removed
if getent passwd "$EXTRA_UID0" >/dev/null; then
    emit extra_uid0_removed 3 false "UID-0 dup $EXTRA_UID0 still present" ""
else
    emit extra_uid0_removed 3 true "" ""
fi

# 2. backdoor user removed
if getent passwd "$BACKDOOR" >/dev/null; then
    emit backdoor_user_removed 3 false "$BACKDOOR still present" ""
else
    emit backdoor_user_removed 3 true "" ""
fi

# 3. sudoers drop-in removed
if [ -f "/etc/sudoers.d/${SUDOERS_DROP}" ]; then
    emit sudoers_drop_removed 2 false "drop-in still present" ""
else
    emit sudoers_drop_removed 2 true "" ""
fi

# 4. rogue yum repo removed + gpgcheck=1 globally
if [ -f "/etc/yum.repos.d/${ROGUE_REPO}.repo" ]; then
    emit rogue_yum_repo_removed 2 false "$ROGUE_REPO.repo still present" ""
else
    emit rogue_yum_repo_removed 2 true "" ""
fi
if grep -qE '^gpgcheck\s*=\s*0' /etc/yum.conf; then
    emit yum_gpgcheck_on 1 false "gpgcheck=0 in yum.conf" ""
else
    emit yum_gpgcheck_on 1 true "" ""
fi

# 5. firewalld represented as enabled (file-state contract)
if [ -f /etc/sysrepair/firewalld.disabled ]; then
    emit firewalld_enabled 2 false "firewalld.disabled marker still present" ""
else
    emit firewalld_enabled 2 true "" ""
fi
if grep -qE '^DefaultZone\s*=\s*trusted' /etc/firewalld/firewalld.conf 2>/dev/null; then
    emit firewalld_default_zone 1 false "default zone still 'trusted'" ""
else
    emit firewalld_default_zone 1 true "" ""
fi

# 6. SELinux config enforcing
if grep -qE '^SELINUX\s*=\s*enforcing' /etc/selinux/config 2>/dev/null; then
    emit selinux_enforcing 2 true "" ""
else
    emit selinux_enforcing 2 false "SELINUX not enforcing in /etc/selinux/config" ""
fi
# Booleans file cleared / httpd ones flipped back
if grep -qE 'httpd_can_network_connect\s*=\s*on' /etc/sysrepair/selinux-booleans 2>/dev/null; then
    emit selinux_booleans_tightened 1 false "httpd_can_network_connect still on" ""
else
    emit selinux_booleans_tightened 1 true "" ""
fi

# 7. trojan binary removed or replaced
if [ ! -f "$TROJAN" ] || ! grep -q "hs-keys" "$TROJAN" 2>/dev/null; then
    emit trojan_removed 3 true "" ""
else
    emit trojan_removed 3 false "$TROJAN still writes to /tmp/.hs-keys" ""
fi

# 8. SUID plant neutralized
if [ -u "$SUID_PLANT" ] 2>/dev/null; then
    emit suid_plant_neutralized 2 false "$SUID_PLANT still has SUID" ""
else
    emit suid_plant_neutralized 2 true "" ""
fi

# 9. rogue cron gone
if [ -f "$CRON_PATH" ]; then
    emit rogue_cron_removed 2 false "$CRON_PATH still present" ""
else
    emit rogue_cron_removed 2 true "" ""
fi

# 10. listener port silent (best-effort — cron may not have fired in time)
if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE ":${LISTENER_PORT}$"; then
    emit listener_silent 2 false "port ${LISTENER_PORT} listening" ""
else
    emit listener_silent 2 true "" ""
fi

# 11. sshd hardened
if grep -qE '^PermitRootLogin\s+yes' /etc/ssh/sshd_config; then
    emit sshd_permit_root_no 2 false "PermitRootLogin still yes" ""
else
    emit sshd_permit_root_no 2 true "" ""
fi
if grep -qE '^PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config; then
    emit sshd_no_empty_pw 1 false "PermitEmptyPasswords still yes" ""
else
    emit sshd_no_empty_pw 1 true "" ""
fi

# 12. PAM pwquality restored
if grep -qE 'pam_pwquality\.so' /etc/pam.d/system-auth 2>/dev/null; then
    emit pam_pwquality_present 1 true "" ""
else
    emit pam_pwquality_present 1 false "pam_pwquality missing from system-auth" ""
fi

# 13. httpd ServerTokens hardened
if grep -qE '^ServerTokens\s+(Prod|ProductOnly|OS|Minimal)' /etc/httpd/conf/httpd.conf; then
    emit httpd_server_tokens 1 true "" ""
else
    emit httpd_server_tokens 1 false "ServerTokens still Full/default" ""
fi
if [ -f /etc/httpd/conf.d/hivestorm-status.conf ] && \
   grep -qE 'Require all granted' /etc/httpd/conf.d/hivestorm-status.conf; then
    emit httpd_status_restricted 1 false "/server-status still world-granted" ""
else
    emit httpd_status_restricted 1 true "" ""
fi

# 14. mariadb bind-address not 0.0.0.0
if grep -qE '^bind-address\s*=\s*0\.0\.0\.0' /etc/my.cnf.d/hivestorm.cnf 2>/dev/null; then
    emit mariadb_bind_localhost 1 false "bind-address still 0.0.0.0" ""
else
    emit mariadb_bind_localhost 1 true "" ""
fi

# 15. vsftpd anonymous off OR package removed
if [ ! -f /etc/vsftpd/vsftpd.conf ] || \
   grep -qE '^anonymous_enable\s*=\s*NO' /etc/vsftpd/vsftpd.conf; then
    emit vsftpd_anon_off 1 true "" ""
else
    emit vsftpd_anon_off 1 false "vsftpd anonymous_enable still YES" ""
fi

# 16. telnet-server disabled
if [ -f /etc/xinetd.d/telnet ] && ! grep -qE '^\s*disable\s*=\s*yes' /etc/xinetd.d/telnet; then
    emit telnet_disabled 1 false "telnet still enabled in xinetd" ""
else
    emit telnet_disabled 1 true "" ""
fi

# 17. /etc/shadow perms tight
mode=$(stat -c %a /etc/shadow 2>/dev/null || echo "")
if [ "$mode" = "0" ] || [ "$mode" = "400" ] || [ "$mode" = "440" ] || [ "$mode" = "640" ]; then
    emit shadow_perms_tight 1 true "" ""
else
    emit shadow_perms_tight 1 false "shadow mode $mode" ""
fi

# ---- service probes ---------------------------------------------------------
if id "$ADMIN" >/dev/null 2>&1; then
    emit admin_preserved 0 true "" service
else
    emit admin_preserved 0 false "$ADMIN deleted" service
fi

if curl -fsS -o /dev/null http://127.0.0.1:80/ 2>/dev/null || \
   curl -fsS -o /dev/null http://127.0.0.1:80/public/ 2>/dev/null; then
    emit httpd_up 0 true "" service
else
    emit httpd_up 0 false "httpd not responding on :80" service
fi

if mysqladmin --socket=/var/lib/mysql/mysql.sock ping >/dev/null 2>&1 || \
   ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE ':3306$'; then
    emit mariadb_up 0 true "" service
else
    emit mariadb_up 0 false "mariadb not listening" service
fi

if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE ':22$'; then
    emit sshd_up 0 true "" service
else
    emit sshd_up 0 false "sshd not listening" service
fi

exit 0
