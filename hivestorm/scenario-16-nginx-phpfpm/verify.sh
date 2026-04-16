#!/usr/bin/env bash
# Hivestorm scenario-16 verifier. JSONL on stdout.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user           "$ROLES")
BACKDOOR=$(jq -r .backdoor_user     "$ROLES")
WEBSHELL=$(jq -r .webshell_path     "$ROLES")
PRIVATE_VHOST=$(jq -r .private_vhost_name "$ROLES")
TROJAN=$(jq -r .trojan_path         "$ROLES")
CRON_PATH=$(jq -r .cron_path        "$ROLES")
LISTENER_PORT=$(jq -r .listener_port "$ROLES")

emit() {
    local cat=""
    if [ -n "${5-}" ]; then cat=",\"category\":\"$5\""; fi
    printf '{"check":"%s","weight":%s,"pass":%s,"reason":%s%s}\n' \
        "$1" "$2" "$3" "$(jq -Rn --arg r "$4" '$r')" "$cat"
}

# 1. backdoor user removed
if getent passwd "$BACKDOOR" >/dev/null; then
    emit backdoor_user_removed 3 false "$BACKDOOR still present" ""
else
    emit backdoor_user_removed 3 true "" ""
fi
if [ -f "/etc/sudoers.d/90-${BACKDOOR}" ]; then
    emit backdoor_sudoers_removed 2 false "sudoers drop-in still present" ""
else
    emit backdoor_sudoers_removed 2 true "" ""
fi

# 2. webshell removed
if [ -f "$WEBSHELL" ]; then
    emit webshell_removed 3 false "$WEBSHELL still present" ""
else
    emit webshell_removed 3 true "" ""
fi

# 3. trojan SUID neutralized
if [ -u "$TROJAN" ] 2>/dev/null; then
    emit trojan_suid_off 2 false "$TROJAN still SUID" ""
else
    emit trojan_suid_off 2 true "" ""
fi

# 4. rogue cron / listener
if [ -f "$CRON_PATH" ]; then
    emit rogue_cron_removed 2 false "$CRON_PATH still present" ""
else
    emit rogue_cron_removed 2 true "" ""
fi
if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE ":${LISTENER_PORT}$"; then
    emit listener_silent 2 false "port ${LISTENER_PORT} listening" ""
else
    emit listener_silent 2 true "" ""
fi

# 5. PHP-FPM pool not running as root
POOL=/etc/php/8.2/fpm/pool.d/www.conf
if grep -qE '^user\s*=\s*root' "$POOL"; then
    emit phpfpm_pool_nonroot 3 false "pool user still root" ""
else
    emit phpfpm_pool_nonroot 3 true "" ""
fi
if grep -qE '^listen\.mode\s*=\s*0666' "$POOL"; then
    emit phpfpm_socket_perms 1 false "socket mode still 0666" ""
else
    emit phpfpm_socket_perms 1 true "" ""
fi

# 6. php.ini: cgi.fix_pathinfo=0, display_errors=Off, allow_url_include=Off
PHP_INI=/etc/php/8.2/fpm/php.ini
if grep -qE '^cgi\.fix_pathinfo\s*=\s*1' "$PHP_INI"; then
    emit php_fix_pathinfo_off 2 false "cgi.fix_pathinfo still 1" ""
else
    emit php_fix_pathinfo_off 2 true "" ""
fi
if grep -qE '^display_errors\s*=\s*On' "$PHP_INI"; then
    emit php_display_errors_off 1 false "display_errors still On" ""
else
    emit php_display_errors_off 1 true "" ""
fi
if grep -qE '^allow_url_include\s*=\s*On' "$PHP_INI"; then
    emit php_allow_url_include_off 2 false "allow_url_include still On" ""
else
    emit php_allow_url_include_off 2 true "" ""
fi

# 7. nginx: no fastcgi_pass without try_files guard
NGX=/etc/nginx/sites-available/default
if grep -qE 'try_files' "$NGX" && grep -qE 'fastcgi_pass' "$NGX"; then
    emit nginx_fastcgi_guard 2 true "" ""
else
    emit nginx_fastcgi_guard 2 false "fastcgi_pass block lacks try_files guard" ""
fi
# autoindex off
if grep -qE '^\s*autoindex\s+on' "$NGX"; then
    emit nginx_autoindex_off 1 false "autoindex still on" ""
else
    emit nginx_autoindex_off 1 true "" ""
fi
# server_tokens off
if grep -qE '^\s*server_tokens\s+on' "$NGX"; then
    emit nginx_server_tokens 1 false "server_tokens still on" ""
else
    emit nginx_server_tokens 1 true "" ""
fi

# 8. private catch-all vhost disabled
if [ -L "/etc/nginx/sites-enabled/${PRIVATE_VHOST}" ] || \
   [ -f "/etc/nginx/sites-enabled/${PRIVATE_VHOST}" ]; then
    emit private_vhost_disabled 2 false "private vhost still enabled" ""
else
    emit private_vhost_disabled 2 true "" ""
fi

# 9. sshd hardened
if grep -qE '^PermitRootLogin\s+yes' /etc/ssh/sshd_config; then
    emit sshd_permit_root_no 2 false "PermitRootLogin still yes" ""
else
    emit sshd_permit_root_no 2 true "" ""
fi

# ---- service probes ---------------------------------------------------------
if id "$ADMIN" >/dev/null 2>&1; then
    emit admin_preserved 0 true "" service
else
    emit admin_preserved 0 false "$ADMIN deleted" service
fi

if curl -fsS -o /dev/null -H "Host: localhost" http://127.0.0.1/ 2>/dev/null; then
    emit nginx_up 0 true "" service
else
    emit nginx_up 0 false "nginx not responding on :80" service
fi

if [ -S /run/php/php8.2-fpm.sock ]; then
    emit phpfpm_up 0 true "" service
else
    emit phpfpm_up 0 false "php-fpm socket missing" service
fi

if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE ':22$'; then
    emit sshd_up 0 true "" service
else
    emit sshd_up 0 false "sshd not listening" service
fi

exit 0
