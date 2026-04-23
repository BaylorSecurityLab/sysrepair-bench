#!/usr/bin/env bash
# Hivestorm scenario-16 verifier — strict behavioural.
# Every non-service probe exercises the live nginx/php-fpm/sshd stack
# (curl to PHP probes for pool UID / pathinfo RCE / display_errors /
# allow_url_include / autoindex / server_tokens / private-vhost leak,
# sshpass login attempts, sudo -n as backdoor, SUID trojan euid probe,
# /dev/tcp listener connect) and AND-gates config state with runtime
# behaviour. JSONL on stdout.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user            "$ROLES")
BACKDOOR=$(jq -r .backdoor_user      "$ROLES")
WEBSHELL=$(jq -r .webshell_path      "$ROLES")
PRIVATE_VHOST=$(jq -r .private_vhost_name "$ROLES")
TROJAN=$(jq -r .trojan_path          "$ROLES")
CRON_PATH=$(jq -r .cron_path         "$ROLES")
LISTENER_PORT=$(jq -r .listener_port "$ROLES")

emit() {
    local cat=""
    if [ -n "${5-}" ]; then cat=",\"category\":\"$5\""; fi
    printf '{"check":"%s","weight":%s,"pass":%s,"reason":%s%s}\n' \
        "$1" "$2" "$3" "$(jq -Rn --arg r "$4" '$r')" "$cat"
}

# Wait for nginx + php-fpm warmup.
for _ in $(seq 1 20); do
    [ -S /run/php/php8.2-fpm.sock ] \
        && curl -fsS -o /dev/null --max-time 2 http://127.0.0.1/ 2>/dev/null \
        && break
    sleep 1
done

# Compute webshell URL from its on-disk path.
WS_URL=""
case "$WEBSHELL" in
    /var/www/uploads/*) WS_URL="http://127.0.0.1/uploads/${WEBSHELL#/var/www/uploads/}" ;;
    /var/www/html/*)    WS_URL="http://127.0.0.1/${WEBSHELL#/var/www/html/}" ;;
esac

# -----------------------------------------------------------------------------
# 1. backdoor user removed — passwd AND SSH login attempt
ent=false; login_ok=false
getent passwd "$BACKDOOR" >/dev/null && ent=true
sshpass -p "${BACKDOOR}-pass" ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 \
    "${BACKDOOR}@127.0.0.1" 'true' >/dev/null 2>&1 && login_ok=true
if $ent || $login_ok; then
    emit backdoor_user_removed 3 false "ent=$ent ssh=$login_ok"
else
    emit backdoor_user_removed 3 true ""
fi

# 2. backdoor sudoers drop-in removed — file AND sudo -n as backdoor works
fpresent=false; sudo_ok=false
[ -f "/etc/sudoers.d/90-${BACKDOOR}" ] && fpresent=true
if getent passwd "$BACKDOOR" >/dev/null; then
    su - "$BACKDOOR" -c 'sudo -n id' >/dev/null 2>&1 && sudo_ok=true
fi
if $fpresent || $sudo_ok; then
    emit backdoor_sudoers_removed 2 false "file=$fpresent sudo=$sudo_ok"
else
    emit backdoor_sudoers_removed 2 true ""
fi

# 3. webshell removed — file AND HTTP RCE via ?c=id
fpresent=false; exec_ok=false
[ -f "$WEBSHELL" ] && fpresent=true
if [ -n "$WS_URL" ]; then
    body=$(curl -sS --max-time 5 "${WS_URL}?c=id" 2>/dev/null)
    printf '%s' "$body" | grep -q 'uid=' && exec_ok=true
fi
if $fpresent || $exec_ok; then
    emit webshell_removed 3 false "file=$fpresent exec=$exec_ok"
else
    emit webshell_removed 3 true ""
fi

# 4. trojan SUID neutralized — bit AND behavioural euid=0 via probe user
suid_bit=false; esc_ok=false
[ -u "$TROJAN" ] 2>/dev/null && suid_bit=true
probe_u="_hs_troj_$$"
useradd -m -s /bin/bash "$probe_u" >/dev/null 2>&1
if [ -x "$TROJAN" ]; then
    euid=$(su - "$probe_u" -c "$TROJAN -p -c 'id -u'" 2>/dev/null)
    [ "$euid" = "0" ] && esc_ok=true
fi
userdel -r "$probe_u" >/dev/null 2>&1
if $suid_bit || $esc_ok; then
    emit trojan_suid_off 2 false "suid=$suid_bit euid0=$esc_ok"
else
    emit trojan_suid_off 2 true ""
fi

# 5. rogue cron drop-in removed — file check
if [ -f "$CRON_PATH" ]; then
    emit rogue_cron_removed 2 false "$CRON_PATH still present"
else
    emit rogue_cron_removed 2 true ""
fi

# 6. listener silent — ss + /dev/tcp connect
listen=false; connect_ok=false
ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq ":${LISTENER_PORT}$" && listen=true
exec 9<>"/dev/tcp/127.0.0.1/${LISTENER_PORT}" 2>/dev/null \
    && { connect_ok=true; exec 9<&- 9>&-; }
if $listen || $connect_ok; then
    emit listener_silent 2 false "listen=$listen connect=$connect_ok"
else
    emit listener_silent 2 true ""
fi

# 7. PHP-FPM pool not root — config AND HTTP probe returning posix_getuid()
POOL=/etc/php/8.2/fpm/pool.d/www.conf
cfg_root=false; runtime_root=false
grep -qE '^user\s*=\s*root' "$POOL" && cfg_root=true
probef=/var/www/html/_hs_uidprobe_$$.php
echo '<?php echo posix_getuid(); ?>' > "$probef" 2>/dev/null
uid=$(curl -sS --max-time 5 "http://127.0.0.1/${probef##*/}" 2>/dev/null)
rm -f "$probef"
[ "$uid" = "0" ] && runtime_root=true
if $cfg_root || $runtime_root; then
    emit phpfpm_pool_nonroot 3 false "cfg_root=$cfg_root runtime_uid0=$runtime_root"
else
    emit phpfpm_pool_nonroot 3 true ""
fi

# 8. PHP-FPM socket perms — mode AND non-root can write to socket
mode_bad=false; nongrp_ok=false
mode=absent
if [ -S /run/php/php8.2-fpm.sock ]; then
    mode=$(stat -c '%a' /run/php/php8.2-fpm.sock)
    case "$mode" in 666|667|676|766|777) mode_bad=true ;; esac
fi
probe_u="_hs_phps_$$"
useradd -m -s /bin/bash "$probe_u" >/dev/null 2>&1
su - "$probe_u" -c 'test -w /run/php/php8.2-fpm.sock' 2>/dev/null && nongrp_ok=true
userdel -r "$probe_u" >/dev/null 2>&1
if $mode_bad || $nongrp_ok; then
    emit phpfpm_socket_perms 1 false "mode=$mode nongrp_writable=$nongrp_ok"
else
    emit phpfpm_socket_perms 1 true ""
fi

# 9. php cgi.fix_pathinfo=0 — config AND HTTP pathinfo RCE
PHP_INI=/etc/php/8.2/fpm/php.ini
cfg_bad=false; exec_ok=false
grep -qE '^cgi\.fix_pathinfo\s*=\s*1' "$PHP_INI" && cfg_bad=true
benign=/var/www/html/_hs_benign_$$.txt
echo '<?php echo "HS_PATHINFO_PWNED"; ?>' > "$benign" 2>/dev/null
body=$(curl -sS --max-time 5 "http://127.0.0.1/${benign##*/}/fake.php" 2>/dev/null)
rm -f "$benign"
printf '%s' "$body" | grep -q 'HS_PATHINFO_PWNED' && exec_ok=true
if $cfg_bad || $exec_ok; then
    emit php_fix_pathinfo_off 2 false "cfg=$cfg_bad pathinfo_exec=$exec_ok"
else
    emit php_fix_pathinfo_off 2 true ""
fi

# 10. php display_errors=Off — config AND HTTP error-leak body
cfg_bad=false; live_bad=false
grep -qE '^display_errors\s*=\s*On' "$PHP_INI" && cfg_bad=true
errf=/var/www/html/_hs_err_$$.php
echo '<?php echo $hs_undef_var_xyz; strlen($hs_undef_var_xyz); ?>' > "$errf" 2>/dev/null
body=$(curl -sS --max-time 5 "http://127.0.0.1/${errf##*/}" 2>/dev/null)
rm -f "$errf"
printf '%s' "$body" | grep -qiE 'warning|undefined' && live_bad=true
if $cfg_bad || $live_bad; then
    emit php_display_errors_off 1 false "cfg=$cfg_bad body_leak=$live_bad"
else
    emit php_display_errors_off 1 true ""
fi

# 11. php allow_url_include=Off — config AND runtime ini_get via HTTP
cfg_bad=false; live_bad=false
grep -qE '^allow_url_include\s*=\s*On' "$PHP_INI" && cfg_bad=true
auif=/var/www/html/_hs_aui_$$.php
echo '<?php echo ini_get("allow_url_include") ? "HS_ON" : "HS_OFF"; ?>' > "$auif" 2>/dev/null
body=$(curl -sS --max-time 5 "http://127.0.0.1/${auif##*/}" 2>/dev/null)
rm -f "$auif"
printf '%s' "$body" | grep -q 'HS_ON' && live_bad=true
if $cfg_bad || $live_bad; then
    emit php_allow_url_include_off 2 false "cfg=$cfg_bad runtime_on=$live_bad"
else
    emit php_allow_url_include_off 2 true ""
fi

# 12. nginx fastcgi guard — config AND /nonexistent.jpg/fake.php does not
#     reach php-fpm (no "File not found" leak, no 200 from fpm).
NGX=/etc/nginx/sites-available/default
guarded=false; leak=false
grep -qE '^\s*try_files' "$NGX" && guarded=true
body=$(curl -sS --max-time 5 "http://127.0.0.1/nonexistent.jpg/fake.php" 2>/dev/null)
printf '%s' "$body" | grep -qi 'file not found' && leak=true
if $guarded && ! $leak; then
    emit nginx_fastcgi_guard 2 true ""
else
    emit nginx_fastcgi_guard 2 false "guarded=$guarded php_fpm_leak=$leak"
fi

# 13. nginx autoindex off — config AND /uploads/ body has no "Index of"
cfg_on=false; live_on=false
grep -qE '^\s*autoindex\s+on' "$NGX" && cfg_on=true
body=$(curl -sS --max-time 5 "http://127.0.0.1/uploads/" 2>/dev/null)
printf '%s' "$body" | grep -qi 'index of' && live_on=true
if $cfg_on || $live_on; then
    emit nginx_autoindex_off 1 false "cfg=$cfg_on body_list=$live_on"
else
    emit nginx_autoindex_off 1 true ""
fi

# 14. nginx server_tokens off — config AND Server header lacks version
cfg_on=false; live_on=false
grep -qE '^\s*server_tokens\s+on' "$NGX" && cfg_on=true
srv=$(curl -sSI --max-time 5 "http://127.0.0.1/" 2>/dev/null \
    | awk -F': ' 'tolower($1)=="server"{print $2}' | tr -d '\r')
printf '%s' "$srv" | grep -Eq 'nginx/[0-9]' && live_on=true
if $cfg_on || $live_on; then
    emit nginx_server_tokens 1 false "cfg=$cfg_on header=$srv"
else
    emit nginx_server_tokens 1 true ""
fi

# 15. private catch-all vhost disabled — link absent AND Host: probe cannot
#     read /notes.txt.
link=false; live=false
if [ -L "/etc/nginx/sites-enabled/${PRIVATE_VHOST}" ] \
   || [ -f "/etc/nginx/sites-enabled/${PRIVATE_VHOST}" ]; then
    link=true
fi
body=$(curl -sS --max-time 5 -H "Host: ${PRIVATE_VHOST}" \
    "http://127.0.0.1/notes.txt" 2>/dev/null)
printf '%s' "$body" | grep -q 'secret-internal' && live=true
if $link || $live; then
    emit private_vhost_disabled 2 false "link=$link leak=$live"
else
    emit private_vhost_disabled 2 true ""
fi

# 16. sshd PermitRootLogin no — effective sshd -T
cfg_bad=false
eff=$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print tolower($2)}')
[ "$eff" = "yes" ] && cfg_bad=true
if $cfg_bad; then
    emit sshd_permit_root_no 2 false "effective=$eff"
else
    emit sshd_permit_root_no 2 true ""
fi

# ---- service probes (weight:0) ----------------------------------------------
if id "$ADMIN" >/dev/null 2>&1; then
    emit admin_preserved 0 true "" service
else
    emit admin_preserved 0 false "$ADMIN deleted" service
fi

if curl -fsS -o /dev/null --max-time 5 http://127.0.0.1/ 2>/dev/null; then
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
