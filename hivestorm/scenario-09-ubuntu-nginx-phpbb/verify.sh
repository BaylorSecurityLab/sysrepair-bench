#!/bin/bash
# Hivestorm HS23 scenario-09 verifier — JSONL on stdout.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user                "$ROLES")
HIDDEN=$(jq -r .hidden_user              "$ROLES")
UNAUTH=$(jq -r .unauthorized_user        "$ROLES")
NONADMIN=$(jq -r .nonadmin_user          "$ROLES")
PROH_PKG=$(jq -r .prohibited_package     "$ROLES")
PROH_BIN=$(jq -r .prohibited_binary_path "$ROLES")
MP3_PATH=$(jq -r .prohibited_mp3_path    "$ROLES")
WEB_DROP=$(jq -r .webroot_drop_path      "$ROLES")
RUBY_PATH=$(jq -r .ruby_unit_path        "$ROLES")
SOCAT_BIN=$(jq -r .socat_trojan_path     "$ROLES")
SOCAT_CRON=$(jq -r .socat_cron_path      "$ROLES")

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

# 4. nonadmin not in sudo
if id "$NONADMIN" >/dev/null 2>&1 && id -nG "$NONADMIN" | tr ' ' '\n' | grep -qx sudo; then
    emit nonadmin_not_sudo 2 false "$NONADMIN in sudo"
else
    emit nonadmin_not_sudo 2 true ""
fi

# 5. PAM pam_unix uses sha512 or yescrypt (not md5)
if grep -Eq 'pam_unix\.so.*\bmd5\b' /etc/pam.d/common-password 2>/dev/null; then
    emit pam_unix_strong_hash 2 false "md5 still set"
else
    emit pam_unix_strong_hash 2 true ""
fi

# 6. PAM pwquality loaded
if grep -REq 'pam_pwquality\.so' /etc/pam.d/ 2>/dev/null; then
    emit pam_pwquality_loaded 2 true ""
else
    emit pam_pwquality_loaded 2 false "pam_pwquality not active"
fi

# 7. sudoers !authenticate removed
if grep -Eq '^[^#]*Defaults\s+!authenticate' /etc/sudoers 2>/dev/null; then
    emit sudoers_authenticate 3 false "!authenticate present"
else
    emit sudoers_authenticate 3 true ""
fi

# 8. sysctl synack_retries == 2
SYNRETRY=$(sysctl -n net.ipv4.tcp_synack_retries 2>/dev/null)
if [ "$SYNRETRY" = "2" ]; then
    emit sysctl_synack 1 true ""
else
    emit sysctl_synack 1 false "synack_retries=$SYNRETRY"
fi

# 9. sysctl kptr_restrict >= 1
KPTR=$(sysctl -n kernel.kptr_restrict 2>/dev/null)
if [ -n "$KPTR" ] && [ "$KPTR" -ge 1 ] 2>/dev/null; then
    emit sysctl_kptr 1 true ""
else
    emit sysctl_kptr 1 false "kptr_restrict=$KPTR"
fi

# 10. UFW enabled
if grep -Eq '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null \
   || ufw status 2>/dev/null | grep -qi 'Status: active'; then
    emit ufw_enabled 2 true ""
else
    emit ufw_enabled 2 false "ufw still disabled"
fi

# 11. nginx server_tokens off
if grep -Eq '^\s*server_tokens\s+off\s*;' /etc/nginx/nginx.conf 2>/dev/null \
   || grep -REq '^\s*server_tokens\s+off\s*;' /etc/nginx/conf.d /etc/nginx/sites-enabled 2>/dev/null; then
    emit nginx_server_tokens 2 true ""
else
    emit nginx_server_tokens 2 false "server_tokens not off"
fi

# 12. nginx X-XSS-Protection header
if grep -REq 'add_header\s+X-XSS-Protection' /etc/nginx/ 2>/dev/null; then
    emit nginx_xss_header 2 true ""
else
    emit nginx_xss_header 2 false "X-XSS-Protection missing"
fi

# 13. mysql bind_address = localhost / 127.0.0.1
if grep -REq '^\s*bind[-_]address\s*=\s*(127\.0\.0\.1|localhost)' /etc/mysql/ 2>/dev/null; then
    emit mysql_bind_local 2 true ""
else
    emit mysql_bind_local 2 false "bind_address not local"
fi

# 14. SSH PermitRootLogin no
if grep -Eqi '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config 2>/dev/null; then
    emit ssh_no_root 2 true ""
else
    emit ssh_no_root 2 false "PermitRootLogin not no"
fi

# 15. phpbb webroot drop removed
if [ -f "$WEB_DROP" ]; then
    emit webroot_drop_removed 2 false "$WEB_DROP present"
else
    emit webroot_drop_removed 2 true ""
fi

# 16. prohibited mp3 removed
if [ -f "$MP3_PATH" ]; then
    emit prohibited_mp3_removed 2 false "$MP3_PATH present"
else
    emit prohibited_mp3_removed 2 true ""
fi

# 17. prohibited apt package removed
if dpkg -l "$PROH_PKG" 2>/dev/null | grep -Eq '^ii'; then
    emit prohibited_package_removed 2 false "$PROH_PKG installed"
else
    emit prohibited_package_removed 2 true ""
fi

# 18. prohibited binary file removed
if [ -f "$PROH_BIN" ]; then
    emit prohibited_binary_removed 2 false "$PROH_BIN present"
else
    emit prohibited_binary_removed 2 true ""
fi

# 19. ruby systemd unit removed
if [ -f "$RUBY_PATH" ]; then
    emit ruby_unit_removed 3 false "$RUBY_PATH present"
else
    emit ruby_unit_removed 3 true ""
fi

# 20. socat cron persistence removed
if [ -f "$SOCAT_CRON" ]; then
    emit socat_cron_removed 3 false "$SOCAT_CRON present"
else
    emit socat_cron_removed 3 true ""
fi

# 21. socat trojan binary removed
if [ -f "$SOCAT_BIN" ]; then
    emit socat_binary_removed 3 false "$SOCAT_BIN present"
else
    emit socat_binary_removed 3 true ""
fi

# ---- service probes ----------------------------------------------------------
if id "$ADMIN" >/dev/null 2>&1; then
    emit admin_user_preserved 0 true "" service
else
    emit admin_user_preserved 0 false "$ADMIN deleted" service
fi

if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':80$'; then
    emit nginx_up 0 true "" service
else
    emit nginx_up 0 false "nginx not listening on :80" service
fi

exit 0
