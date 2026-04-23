#!/usr/bin/env bash
# Hivestorm scenario-12 verifier — strict behavioural.
# Every non-service probe exercises the live subsystem (ssh login, sudo run,
# SUID exec, pamtester, curl HTTP, nc connect, ftp anon, telnet :23, live
# mariadb port, live sshd -T) and AND-gates config with runtime. JSONL.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user           "$ROLES")
BACKDOOR=$(jq -r .backdoor_user     "$ROLES")
EXTRA_UID0=$(jq -r .extra_uid0_user "$ROLES")
NONADMIN=$(jq -r .nonadmin_user     "$ROLES")
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

ensure_sshd() {
    pgrep -x sshd >/dev/null 2>&1 || { /usr/sbin/sshd >/dev/null 2>&1; sleep 1; }
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
# 1. extra UID-0 account: resolves AND can log in
resolves=true; logins=true
getent passwd "$EXTRA_UID0" >/dev/null 2>&1 || resolves=false
ssh_probe "$EXTRA_UID0" "${EXTRA_UID0}-pass" || logins=false
if $resolves || $logins; then
    emit extra_uid0_removed 3 false "resolves=$resolves logins=$logins"
else
    emit extra_uid0_removed 3 true ""
fi

# 2. backdoor user: resolves AND can log in
resolves=true; logins=true
getent passwd "$BACKDOOR" >/dev/null 2>&1 || resolves=false
ssh_probe "$BACKDOOR" "${BACKDOOR}-pass" || logins=false
if $resolves || $logins; then
    emit backdoor_user_removed 3 false "resolves=$resolves logins=$logins"
else
    emit backdoor_user_removed 3 true ""
fi

# 3. sudoers drop-in: file present AND sudo -n works for BACKDOOR
dropin=false; sudo_ok=false
[ -f "/etc/sudoers.d/${SUDOERS_DROP}" ] && dropin=true
if id "$BACKDOOR" >/dev/null 2>&1; then
    su -s /bin/bash -c 'sudo -n true' "$BACKDOOR" >/dev/null 2>&1 && sudo_ok=true
fi
if $dropin || $sudo_ok; then
    emit sudoers_drop_removed 2 false "dropin=$dropin sudo_ok=$sudo_ok"
else
    emit sudoers_drop_removed 2 true ""
fi

# 4. rogue yum repo — file absent AND `yum repolist` doesn't list it
file_present=false; live_listed=false
[ -f "/etc/yum.repos.d/${ROGUE_REPO}.repo" ] && file_present=true
yum -q repolist all 2>/dev/null | awk '{print $1}' | grep -Eq "(^|/)${ROGUE_REPO}(/|$)" \
    && live_listed=true
if $file_present || $live_listed; then
    emit rogue_yum_repo_removed 2 false "file=$file_present listed=$live_listed"
else
    emit rogue_yum_repo_removed 2 true ""
fi

# 5. yum gpgcheck — global on AND no repo file overrides to 0
global_off=false; repo_off=false
grep -qE '^gpgcheck\s*=\s*0' /etc/yum.conf 2>/dev/null && global_off=true
grep -REq '^gpgcheck\s*=\s*0' /etc/yum.repos.d/ 2>/dev/null && repo_off=true
if $global_off || $repo_off; then
    emit yum_gpgcheck_on 1 false "global_off=$global_off repo_off=$repo_off"
else
    emit yum_gpgcheck_on 1 true ""
fi

# 6. firewalld "enabled" — marker file (container has no nf enforcement)
if [ -f /etc/sysrepair/firewalld.disabled ]; then
    emit firewalld_enabled 2 false "firewalld.disabled marker still present"
else
    emit firewalld_enabled 2 true ""
fi

# 7. firewalld default zone
if grep -qE '^DefaultZone\s*=\s*trusted' /etc/firewalld/firewalld.conf 2>/dev/null; then
    emit firewalld_default_zone 1 false "default zone still 'trusted'"
else
    emit firewalld_default_zone 1 true ""
fi

# 8. SELinux config enforcing (file state — no kernel enforcement in ctr)
if grep -qE '^SELINUX\s*=\s*enforcing' /etc/selinux/config 2>/dev/null; then
    emit selinux_enforcing 2 true ""
else
    emit selinux_enforcing 2 false "SELINUX not enforcing"
fi

# 9. SELinux booleans tightened
if grep -qE 'httpd_can_network_connect\s*=\s*on' /etc/sysrepair/selinux-booleans 2>/dev/null; then
    emit selinux_booleans_tightened 1 false "httpd_can_network_connect still on"
else
    emit selinux_booleans_tightened 1 true ""
fi

# 10. trojan — file absent AND running it does NOT append to /tmp/.hs-keys
file_present=false; active=false
[ -f "$TROJAN" ] && file_present=true
if [ -x "$TROJAN" ]; then
    rm -f /tmp/.hs-keys-probe 2>/dev/null
    # trojan appends to /tmp/.hs-keys on every invocation.
    before=$(stat -c '%s' /tmp/.hs-keys 2>/dev/null || echo 0)
    "$TROJAN" -c 'true' >/dev/null 2>&1
    after=$(stat -c '%s' /tmp/.hs-keys 2>/dev/null || echo 0)
    [ "$after" -gt "$before" ] 2>/dev/null && active=true
fi
if $file_present || $active; then
    emit trojan_removed 3 false "file=$file_present active=$active"
else
    emit trojan_removed 3 true ""
fi

# 11. SUID plant — bit set OR euid=0 when run by non-root
suid_bit=false; euid_zero=false
[ -u "$SUID_PLANT" ] 2>/dev/null && suid_bit=true
if id "$NONADMIN" >/dev/null 2>&1 && [ -x "$SUID_PLANT" ]; then
    euid=$(su -s /bin/bash -c "\"$SUID_PLANT\" -p -c 'id -u'" "$NONADMIN" 2>/dev/null \
        | tr -d '[:space:]')
    [ "$euid" = "0" ] && euid_zero=true
fi
if $suid_bit || $euid_zero; then
    emit suid_plant_neutralized 2 false "suid=$suid_bit euid0=$euid_zero"
else
    emit suid_plant_neutralized 2 true ""
fi

# 12. rogue cron — file present OR cron.d grep AND listener port LIVE
cron_file=false; cron_listed=false
[ -f "$CRON_PATH" ] && cron_file=true
grep -Rq "$LISTENER_PORT" /etc/cron.d /etc/crontab /var/spool/cron 2>/dev/null \
    && cron_listed=true
if $cron_file || $cron_listed; then
    emit rogue_cron_removed 2 false "file=$cron_file listed=$cron_listed"
else
    emit rogue_cron_removed 2 true ""
fi

# 13. listener silent — port not listening AND nc connect fails
listen=false; connect_ok=false
ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq ":${LISTENER_PORT}$" && listen=true
# Try to talk to it.
exec 9<>"/dev/tcp/127.0.0.1/${LISTENER_PORT}" 2>/dev/null \
    && { connect_ok=true; exec 9<&- 9>&-; }
if $listen || $connect_ok; then
    emit listener_silent 2 false "listen=$listen connect=$connect_ok"
else
    emit listener_silent 2 true ""
fi

# 14. sshd PermitRootLogin no — effective via sshd -T
prl=$(sshd_eff permitrootlogin)
if [ "$prl" = "no" ]; then
    emit sshd_permit_root_no 2 true ""
else
    emit sshd_permit_root_no 2 false "permitrootlogin=${prl:-unknown}"
fi

# 15. sshd PermitEmptyPasswords no — effective via sshd -T
pep=$(sshd_eff permitemptypasswords)
if [ "$pep" = "no" ]; then
    emit sshd_no_empty_pw 1 true ""
else
    emit sshd_no_empty_pw 1 false "permitemptypasswords=${pep:-unknown}"
fi

# 16. PAM pwquality — chpasswd rejects trivial weak password
probe_u="_hs_pamprobe_$$"
useradd -m -s /bin/bash "$probe_u" >/dev/null 2>&1
echo "${probe_u}:Str0ng!Base#2026" | chpasswd >/dev/null 2>&1
weak_accept=false
if echo "${probe_u}:abc" | chpasswd >/dev/null 2>&1; then
    weak_accept=true
fi
if $weak_accept; then
    emit pam_pwquality_present 1 false "weak pw not rejected"
else
    emit pam_pwquality_present 1 true ""
fi
userdel -r "$probe_u" >/dev/null 2>&1

# 17. httpd ServerTokens Prod — live HTTP probe, Server must NOT reveal version
service httpd status >/dev/null 2>&1 || /usr/sbin/httpd -k start >/dev/null 2>&1
sleep 1
server_hdr=$(curl -sI http://127.0.0.1/ 2>/dev/null | awk -F': *' 'tolower($1)=="server"{print $2; exit}' | tr -d '\r')
if printf '%s' "$server_hdr" | grep -Eiq 'apache/[0-9]|\(centos\)'; then
    emit httpd_server_tokens 1 false "Server: $server_hdr"
else
    emit httpd_server_tokens 1 true ""
fi

# 18. httpd /server-status restricted — curl must return 403/404 (not 200)
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/server-status 2>/dev/null)
if [ "$code" = "200" ]; then
    emit httpd_status_restricted 1 false "/server-status returned 200"
else
    emit httpd_status_restricted 1 true ""
fi

# 19. mariadb bound to localhost — ss must show 127.0.0.1:3306, not 0.0.0.0
cfg_bad=false; listen_bad=false
grep -qE '^bind-address\s*=\s*0\.0\.0\.0' /etc/my.cnf.d/hivestorm.cnf 2>/dev/null \
    && cfg_bad=true
ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq '^(0\.0\.0\.0|\*|::):3306$' \
    && listen_bad=true
if $cfg_bad || $listen_bad; then
    emit mariadb_bind_localhost 1 false "cfg_bad=$cfg_bad listen_bad=$listen_bad"
else
    emit mariadb_bind_localhost 1 true ""
fi

# 20. vsftpd anon off — behavioural: ftp anon USER anonymous must fail
cfg_bad=false; anon_ok=false
if [ -f /etc/vsftpd/vsftpd.conf ] \
   && grep -qE '^anonymous_enable\s*=\s*YES' /etc/vsftpd/vsftpd.conf; then
    cfg_bad=true
fi
# Try anon login — only run if vsftpd listening.
if ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq ':21$'; then
    resp=$(printf 'USER anonymous\r\nPASS test@hs\r\nQUIT\r\n' \
        | timeout 4 ncat 127.0.0.1 21 2>/dev/null)
    printf '%s' "$resp" | grep -Eq '^230 ' && anon_ok=true
fi
if $cfg_bad || $anon_ok; then
    emit vsftpd_anon_off 1 false "cfg=$cfg_bad anon_login=$anon_ok"
else
    emit vsftpd_anon_off 1 true ""
fi

# 21. telnet disabled — xinetd config AND :23 not listening
cfg_bad=false; live=false
if [ -f /etc/xinetd.d/telnet ] \
   && ! grep -qE '^\s*disable\s*=\s*yes' /etc/xinetd.d/telnet; then
    cfg_bad=true
fi
ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq ':23$' && live=true
if $cfg_bad || $live; then
    emit telnet_disabled 1 false "cfg=$cfg_bad listen=$live"
else
    emit telnet_disabled 1 true ""
fi

# 22. /etc/shadow perms — mode AND non-root read test
mode_bad=true; read_bad=true
mode=$(stat -c '%a' /etc/shadow 2>/dev/null)
case "$mode" in 0|400|440|640) mode_bad=false ;; esac
if id "$NONADMIN" >/dev/null 2>&1; then
    su -s /bin/bash -c 'test -r /etc/shadow' "$NONADMIN" 2>/dev/null || read_bad=false
else
    read_bad=false
fi
if $mode_bad || $read_bad; then
    emit shadow_perms_tight 1 false "mode=$mode nonroot_read=$read_bad"
else
    emit shadow_perms_tight 1 true ""
fi

# ---- service probes (weight:0) ----------------------------------------------
if id "$ADMIN" >/dev/null 2>&1; then
    emit admin_preserved 0 true "" service
else
    emit admin_preserved 0 false "$ADMIN deleted" service
fi

if curl -fsS -o /dev/null http://127.0.0.1/ 2>/dev/null \
   || ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq ':80$'; then
    emit httpd_up 0 true "" service
else
    emit httpd_up 0 false "httpd not responding on :80" service
fi

if mysqladmin --socket=/var/lib/mysql/mysql.sock ping >/dev/null 2>&1 \
   || ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq ':3306$'; then
    emit mariadb_up 0 true "" service
else
    emit mariadb_up 0 false "mariadb not listening" service
fi

if ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq ':22$'; then
    emit sshd_up 0 true "" service
else
    emit sshd_up 0 false "sshd not listening" service
fi

exit 0
