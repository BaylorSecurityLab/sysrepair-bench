#!/bin/bash
# Hivestorm HS20 scenario-01 verifier.
# Emits one JSON object per line on stdout. Never short-circuits.
# Schema: {"check": str, "weight": int, "pass": bool, "reason": str,
#          "category"?: "service"}
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user          "$ROLES")
BACKDOOR=$(jq -r .backdoor_user    "$ROLES")
EXTRA_UID0=$(jq -r .extra_uid0_user "$ROLES")
TROJAN=$(jq -r .trojan_path        "$ROLES")
SUID_PLANT=$(jq -r .suid_plant     "$ROLES")
CRON_PATH=$(jq -r .cron_path       "$ROLES")
PORT=$(jq -r .listener_port        "$ROLES")

emit() {
    # $1=check $2=weight $3=pass(true|false) $4=reason [$5=category]
    local cat=""
    if [ -n "${5-}" ]; then cat=",\"category\":\"$5\""; fi
    printf '{"check":"%s","weight":%s,"pass":%s,"reason":%s%s}\n' \
        "$1" "$2" "$3" "$(jq -Rn --arg r "$4" '$r')" "$cat"
}

# ---- hardening checks ---------------------------------------------------------

# 1. extra UID 0 removed
if awk -F: -v u="$EXTRA_UID0" '$1==u && $3==0' /etc/passwd | grep -q .; then
    emit extra_uid0_removed 3 false "$EXTRA_UID0 still has UID 0"
else
    emit extra_uid0_removed 3 true  ""
fi

# 2. backdoor user removed
if id "$BACKDOOR" >/dev/null 2>&1; then
    emit backdoor_user_removed 3 false "$BACKDOOR still exists"
else
    emit backdoor_user_removed 3 true  ""
fi

# 3. sudoers NOPASSWD drop-in for backdoor removed
if [ -f "/etc/sudoers.d/90-${BACKDOOR}" ]; then
    emit backdoor_sudoers_removed 2 false "/etc/sudoers.d/90-${BACKDOOR} exists"
else
    emit backdoor_sudoers_removed 2 true  ""
fi

# 4. rogue cron removed
if [ -e "$CRON_PATH" ]; then
    emit rogue_cron_removed 3 false "$CRON_PATH present"
else
    emit rogue_cron_removed 3 true  ""
fi

# 5. trojaned binary removed or replaced
if [ -f "$TROJAN" ] && cmp -s "$TROJAN" /bin/nc.traditional 2>/dev/null; then
    emit trojan_removed 3 false "$TROJAN still matches netcat"
else
    emit trojan_removed 3 true  ""
fi

# 6. SUID plant neutralized
if [ -f "$SUID_PLANT" ] && [ -u "$SUID_PLANT" ]; then
    emit suid_plant_fixed 3 false "$SUID_PLANT still SUID"
else
    emit suid_plant_fixed 3 true  ""
fi

# 7. backdoor listener silent
if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ":${PORT}\$"; then
    emit backdoor_listener_silent 3 false "port $PORT still listening"
else
    emit backdoor_listener_silent 3 true  ""
fi

# 8. sshd PermitRootLogin no
if grep -Eq '^\s*PermitRootLogin\s+(no|prohibit-password)' /etc/ssh/sshd_config; then
    emit sshd_no_root 2 true  ""
else
    emit sshd_no_root 2 false "PermitRootLogin not restricted"
fi

# 9. sshd PermitEmptyPasswords no
if grep -Eq '^\s*PermitEmptyPasswords\s+no' /etc/ssh/sshd_config; then
    emit sshd_no_empty_pw 1 true  ""
else
    emit sshd_no_empty_pw 1 false "PermitEmptyPasswords not no"
fi

# 10. login.defs PASS_MAX_DAYS <= 365
MAX=$(awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs | tail -n1)
if [ -n "$MAX" ] && [ "$MAX" -le 365 ] 2>/dev/null; then
    emit login_defs_maxdays 1 true  ""
else
    emit login_defs_maxdays 1 false "PASS_MAX_DAYS=${MAX:-unset}"
fi

# 11. /etc/shadow perms tight
MODE=$(stat -c '%a' /etc/shadow)
if [ "$MODE" = "640" ] || [ "$MODE" = "600" ] || [ "$MODE" = "000" ]; then
    emit shadow_perms 2 true  ""
else
    emit shadow_perms 2 false "mode=$MODE"
fi

# 12/13. sysctl
if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "0" ]; then
    emit sysctl_ip_forward 1 true ""
else
    emit sysctl_ip_forward 1 false "ip_forward on"
fi
if [ "$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)" = "0" ]; then
    emit sysctl_accept_redirects 1 true ""
else
    emit sysctl_accept_redirects 1 false "accept_redirects on"
fi

# 14. apache ServerTokens
if grep -REq '^\s*ServerTokens\s+(Prod|Minimal|OS)' /etc/apache2/ 2>/dev/null; then
    emit apache_server_tokens 1 true  ""
else
    emit apache_server_tokens 1 false "ServerTokens not tightened"
fi

# 15. apache Indexes option removed from /var/www/html
if grep -RPzq '(?s)<Directory\s+/var/www/html>.*?Options[^<]*Indexes' /etc/apache2/ 2>/dev/null; then
    emit apache_no_indexes 1 false "Indexes still on /var/www/html"
else
    emit apache_no_indexes 1 true  ""
fi

# 16. PHP allow_url_include off
PHPINI=$(ls /etc/php/*/apache2/php.ini 2>/dev/null | head -n1)
if [ -n "$PHPINI" ] && grep -Eq '^\s*allow_url_include\s*=\s*Off' "$PHPINI"; then
    emit php_no_url_include 1 true  ""
else
    emit php_no_url_include 1 false "allow_url_include not Off"
fi

# 17. mariadb bind-address not 0.0.0.0
if grep -RqE '^\s*bind-address\s*=\s*0\.0\.0\.0' /etc/mysql/ 2>/dev/null; then
    emit mariadb_bind_local 1 false "bind-address=0.0.0.0"
else
    emit mariadb_bind_local 1 true  ""
fi

# ---- regression / service probes (category=service) --------------------------

if id "$ADMIN" >/dev/null 2>&1; then
    emit admin_user_preserved 0 true  "" service
else
    emit admin_user_preserved 0 false "$ADMIN was deleted" service
fi

if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':22$'; then
    emit ssh_up 0 true "" service
else
    emit ssh_up 0 false "sshd not listening" service
fi

if curl -sSf --max-time 5 http://127.0.0.1/ >/dev/null 2>&1; then
    emit apache_up 0 true "" service
else
    emit apache_up 0 false "apache not responding" service
fi

if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':3306$'; then
    emit mysql_up 0 true "" service
else
    emit mysql_up 0 false "mysql not listening" service
fi

exit 0
