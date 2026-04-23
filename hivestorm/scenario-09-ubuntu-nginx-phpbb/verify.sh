#!/bin/bash
# Hivestorm HS23 scenario-09 verifier — strict behavioural.
# Every non-service probe exercises the subsystem (ssh, sudo, pamtester,
# chpasswd + shadow hash, curl HTTP, live kernel sysctl, cron, exec probes)
# and AND-gates config state with runtime behaviour. JSONL on stdout.
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

sshd_eff() {
    /usr/sbin/sshd -T -f /etc/ssh/sshd_config 2>/dev/null \
        | awk -v k="$1" 'tolower($1)==tolower(k){print $2; exit}'
}

# -----------------------------------------------------------------------------
# 1. hidden user: resolves AND can log in
resolves=true; logins=true
id "$HIDDEN" >/dev/null 2>&1 || resolves=false
ssh_probe "$HIDDEN" hidden123 || logins=false
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

# 4. nonadmin not in sudo: group membership OR sudo works behaviourally
grp=false; works=false
if id "$NONADMIN" >/dev/null 2>&1; then
    id -nG "$NONADMIN" | tr ' ' '\n' | grep -qx sudo && grp=true
    # With Defaults !authenticate (seed baseline) sudo -n works without pw.
    su -s /bin/bash -c 'sudo -n true' "$NONADMIN" >/dev/null 2>&1 && works=true
fi
if $grp || $works; then
    emit nonadmin_not_sudo 2 false "grp=$grp works=$works"
else
    emit nonadmin_not_sudo 2 true ""
fi

# 5. PAM hashing: chpasswd a probe user and inspect /etc/shadow hash prefix.
probe_u="_hs_pamprobe_$$"
useradd -m -s /bin/bash "$probe_u" >/dev/null 2>&1
echo "${probe_u}:HashProbe!2026" | chpasswd >/dev/null 2>&1
hash_field=$(getent shadow "$probe_u" | cut -d: -f2)
prefix=$(printf '%s' "$hash_field" | sed -E 's/^(\$[^$]+\$).*/\1/')
case "$prefix" in
    \$6\$|\$y\$|\$7\$) emit pam_unix_strong_hash 2 true "" ;;
    *) emit pam_unix_strong_hash 2 false "new hash prefix=$prefix" ;;
esac

# 6. PAM pwquality — chpasswd rejects a trivially weak password
echo "${probe_u}:Str0ng!Base#2026" | chpasswd >/dev/null 2>&1
weak_accept=false
if echo "${probe_u}:abc" | chpasswd >/dev/null 2>&1; then
    weak_accept=true
fi
if $weak_accept; then
    emit pam_pwquality_loaded 2 false "weak pw not rejected"
else
    emit pam_pwquality_loaded 2 true ""
fi
userdel -r "$probe_u" >/dev/null 2>&1

# 7. sudoers !authenticate removed — config + behavioural
cfg=false; noauth=false
grep -REq '^[^#]*Defaults\s+!authenticate' /etc/sudoers /etc/sudoers.d 2>/dev/null && cfg=true
# If NONADMIN is still in sudo and sudo -n returns 0 without a per-user NOPASSWD,
# !authenticate is still active.
if id "$NONADMIN" >/dev/null 2>&1 \
   && ! ls /etc/sudoers.d/*"$NONADMIN"* 2>/dev/null | xargs -r grep -l NOPASSWD >/dev/null 2>&1 \
   && su -s /bin/bash -c 'sudo -n true' "$NONADMIN" >/dev/null 2>&1; then
    noauth=true
fi
if $cfg || $noauth; then
    emit sudoers_authenticate 3 false "cfg=$cfg noauth=$noauth"
else
    emit sudoers_authenticate 3 true ""
fi

# 8. sysctl tcp_synack_retries = 2 (eff + live AND-gate)
eff=$(eff_sysctl net.ipv4.tcp_synack_retries)
live=$(sysctl -n net.ipv4.tcp_synack_retries 2>/dev/null)
if [ "$eff" = "2" ] && [ "$live" = "2" ]; then
    emit sysctl_synack 1 true ""
else
    emit sysctl_synack 1 false "eff=$eff live=$live"
fi

# 9. sysctl kernel.kptr_restrict >= 1 (eff + live AND-gate)
eff=$(eff_sysctl kernel.kptr_restrict)
live=$(sysctl -n kernel.kptr_restrict 2>/dev/null)
eff_ok=false; live_ok=false
[ -n "$eff"  ] && [ "$eff"  -ge 1 ] 2>/dev/null && eff_ok=true
[ -n "$live" ] && [ "$live" -ge 1 ] 2>/dev/null && live_ok=true
if $eff_ok && $live_ok; then
    emit sysctl_kptr 1 true ""
else
    emit sysctl_kptr 1 false "eff=$eff live=$live"
fi

# 10. UFW enabled — cfg AND live
cfg=false; live=false
grep -Eq '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null && cfg=true
ufw status 2>/dev/null | head -1 | grep -qi 'Status: active' && live=true
if $cfg && $live; then
    emit ufw_enabled 2 true ""
else
    emit ufw_enabled 2 false "cfg=$cfg live=$live"
fi

# 11. nginx server_tokens off — live HTTP probe of Server header
service nginx status >/dev/null 2>&1 || service nginx start >/dev/null 2>&1
sleep 1
server_hdr=$(curl -sI http://127.0.0.1/ 2>/dev/null | awk -F': *' 'tolower($1)=="server"{print $2; exit}' | tr -d '\r')
if [ -n "$server_hdr" ] && printf '%s' "$server_hdr" | grep -Eiq 'nginx/[0-9]'; then
    emit nginx_server_tokens 2 false "Server: $server_hdr"
elif [ -z "$server_hdr" ]; then
    emit nginx_server_tokens 2 false "nginx not responding"
else
    emit nginx_server_tokens 2 true ""
fi

# 12. nginx X-XSS-Protection header — live HTTP probe
xss=$(curl -sI http://127.0.0.1/ 2>/dev/null | awk -F': *' 'tolower($1)=="x-xss-protection"{print $2; exit}' | tr -d '\r')
if [ -n "$xss" ]; then
    emit nginx_xss_header 2 true ""
else
    emit nginx_xss_header 2 false "X-XSS-Protection missing"
fi

# 13. mysql bind_address localhost (file-only; mysql not actually installed)
if grep -REq '^\s*bind[-_]address\s*=\s*(127\.0\.0\.1|localhost)' /etc/mysql/ 2>/dev/null; then
    emit mysql_bind_local 2 true ""
else
    emit mysql_bind_local 2 false "bind_address not local"
fi

# 14. SSH PermitRootLogin no — effective config via sshd -T
prl=$(sshd_eff permitrootlogin)
if [ "$prl" = "no" ]; then
    emit ssh_no_root 2 true ""
else
    emit ssh_no_root 2 false "permitrootlogin=${prl:-unknown}"
fi

# 15. phpbb webroot drop — file absent AND HTTP 404 at webroot path
rel=${WEB_DROP#/var/www/html}
file_present=false; http_ok=false
[ -f "$WEB_DROP" ] && file_present=true
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1${rel}" 2>/dev/null)
[ "$code" = "200" ] && http_ok=true
if $file_present || $http_ok; then
    emit webroot_drop_removed 2 false "file=$file_present http=$code"
else
    emit webroot_drop_removed 2 true ""
fi

# 16. prohibited MP3 removed
if [ -f "$MP3_PATH" ]; then
    emit prohibited_mp3_removed 2 false "$MP3_PATH present"
else
    emit prohibited_mp3_removed 2 true ""
fi

# 17. prohibited apt package — dpkg AND PATH
inst=false; onpath=false
dpkg -l "$PROH_PKG" 2>/dev/null | grep -Eq '^ii' && inst=true
command -v "$PROH_PKG" >/dev/null 2>&1 && onpath=true
if $inst || $onpath; then
    emit prohibited_package_removed 2 false "$PROH_PKG installed=$inst onpath=$onpath"
else
    emit prohibited_package_removed 2 true ""
fi

# 18. prohibited binary — file AND executable
file_present=false; exec_ok=false
[ -f "$PROH_BIN" ] && file_present=true
[ -x "$PROH_BIN" ] && exec_ok=true
if $file_present || $exec_ok; then
    emit prohibited_binary_removed 2 false "file=$file_present exec=$exec_ok"
else
    emit prohibited_binary_removed 2 true ""
fi

# 19. ruby systemd unit — file absent
if [ -f "$RUBY_PATH" ]; then
    emit ruby_unit_removed 3 false "$RUBY_PATH present"
else
    emit ruby_unit_removed 3 true ""
fi

# 20. socat cron persistence — file AND active in cron (/etc/cron.d loaded)
file_present=false; active=false
[ -f "$SOCAT_CRON" ] && file_present=true
# grep effective cron.d (cron re-reads /etc/cron.d on tick; file presence in
# /etc/cron.d IS cron loading it). Supplement: search system crontabs.
grep -REq "$(basename "$SOCAT_BIN")" /etc/cron.d /etc/crontab /var/spool/cron 2>/dev/null \
    && active=true
if $file_present || $active; then
    emit socat_cron_removed 3 false "file=$file_present active=$active"
else
    emit socat_cron_removed 3 true ""
fi

# 21. socat trojan binary — file AND executable
file_present=false; exec_ok=false
[ -f "$SOCAT_BIN" ] && file_present=true
[ -x "$SOCAT_BIN" ] && exec_ok=true
if $file_present || $exec_ok; then
    emit socat_binary_removed 3 false "file=$file_present exec=$exec_ok"
else
    emit socat_binary_removed 3 true ""
fi

# ---- service probes (weight:0) ----------------------------------------------
if id "$ADMIN" >/dev/null 2>&1; then
    emit admin_user_preserved 0 true "" service
else
    emit admin_user_preserved 0 false "$ADMIN deleted" service
fi

if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':80$'; then
    emit nginx_up 0 true "" service
else
    emit nginx_up 0 false "nginx not listening" service
fi

if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':22$'; then
    emit sshd_up 0 true "" service
else
    emit sshd_up 0 false "sshd not listening" service
fi

exit 0
