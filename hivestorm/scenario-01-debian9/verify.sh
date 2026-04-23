#!/bin/bash
# Hivestorm HS20 scenario-01 verifier — strict behavioural + config.
# Every non-service check exercises the subsystem. Baseline = all pass:false.
# JSONL on stdout. Never short-circuits.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user             "$ROLES")
ADMIN_PW=$(jq -r .admin_weak_password "$ROLES")
BACKDOOR=$(jq -r .backdoor_user       "$ROLES")
EXTRA_UID0=$(jq -r .extra_uid0_user   "$ROLES")
TROJAN=$(jq -r .trojan_path           "$ROLES")
SUID_PLANT=$(jq -r .suid_plant        "$ROLES")
CRON_PATH=$(jq -r .cron_path          "$ROLES")
PORT=$(jq -r .listener_port           "$ROLES")

emit() {
    local cat=""
    if [ -n "${5-}" ]; then cat=",\"category\":\"$5\""; fi
    printf '{"check":"%s","weight":%s,"pass":%s,"reason":%s%s}\n' \
        "$1" "$2" "$3" "$(jq -Rn --arg r "$4" '$r')" "$cat"
}

# ---- helpers -----------------------------------------------------------------
eff_sysctl() {
    local key="$1" files
    files=$(ls -1 /run/sysctl.d/*.conf /etc/sysctl.d/*.conf \
        /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf \
        /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null | tr '\n' ' ')
    [ -z "$files" ] && { echo ""; return; }
    awk -v k="$key" '
        { sub(/#.*/,""); if ($0 !~ /=/) next
          n=split($0,a,"="); if (n<2) next
          gsub(/[[:space:]]/,"",a[1])
          if (a[1]==k) { gsub(/^[[:space:]]+|[[:space:]]+$/,"",a[2]); last=a[2] }
        }
        END { print last }
    ' $files 2>/dev/null
}
sshd_eff() { sshd -T -f /etc/ssh/sshd_config 2>/dev/null | awk -v k="$1" 'tolower($1)==k{print $2;exit}'; }

ensure_sshd() {
    if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':22$'; then
        /usr/sbin/sshd -D -e >/tmp/sshd-verify.log 2>&1 &
        for i in 1 2 3 4 5; do
            sleep 1
            ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':22$' && break
        done
    fi
}
ensure_sshd

ssh_probe() {
    local u="$1" pw="$2"
    sshpass -p "$pw" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 -o ConnectTimeout=4 -o LogLevel=ERROR \
        "$u@127.0.0.1" true 2>/dev/null
}

# ---- 1. extra UID 0 removed (live passwd DB + id lookup) --------------------
extra_present=false
getent passwd "$EXTRA_UID0" >/dev/null 2>&1 && extra_present=true
extra_uid=$(id -u "$EXTRA_UID0" 2>/dev/null)
if $extra_present || [ "$extra_uid" = "0" ]; then
    emit extra_uid0_removed 3 false "$EXTRA_UID0 present uid=${extra_uid:-missing}"
else
    emit extra_uid0_removed 3 true ""
fi

# ---- 2. backdoor user removed (live DB + ssh login fails) -------------------
bd_resolves=false; bd_logins=false
getent passwd "$BACKDOOR" >/dev/null 2>&1 && bd_resolves=true
ssh_probe "$BACKDOOR" "changeme" && bd_logins=true
if $bd_resolves || $bd_logins; then
    emit backdoor_user_removed 3 false "resolves=$bd_resolves logins=$bd_logins"
else
    emit backdoor_user_removed 3 true ""
fi

# ---- 3. backdoor sudoers dropin removed + sudo -n denies backdoor -----------
sud_file=false; sud_behav_ok=true
[ -f "/etc/sudoers.d/90-${BACKDOOR}" ] && sud_file=true
if id "$BACKDOOR" >/dev/null 2>&1; then
    if su -s /bin/bash -c 'sudo -n /bin/true' "$BACKDOOR" >/dev/null 2>&1; then
        sud_behav_ok=false
    fi
fi
if ! $sud_file && $sud_behav_ok; then
    emit backdoor_sudoers_removed 2 true ""
else
    emit backdoor_sudoers_removed 2 false "dropin=$sud_file sudo_denied=$sud_behav_ok"
fi

# ---- 4. rogue cron removed (file + beacon string anywhere cron reads) -------
cron_file=false; cron_beacon=false
[ -e "$CRON_PATH" ] && cron_file=true
if grep -R -l "10\.0\.0\.2" /etc/cron.d /etc/crontab /etc/cron.hourly \
      /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
      /var/spool/cron 2>/dev/null | grep -q .; then
    cron_beacon=true
fi
if ! $cron_file && ! $cron_beacon; then
    emit rogue_cron_removed 3 true ""
else
    emit rogue_cron_removed 3 false "file=$cron_file beacon=$cron_beacon"
fi

# ---- 5. trojan no longer behaves as netcat ----------------------------------
trojan_is_nc=false
if [ -f "$TROJAN" ]; then
    [ -f /bin/nc.traditional ] && cmp -s "$TROJAN" /bin/nc.traditional && trojan_is_nc=true
    if "$TROJAN" -h 2>&1 | grep -Eqi '\[-?hklnrtuvz\]|cmd line:|nc -h for help'; then
        trojan_is_nc=true
    fi
fi
if $trojan_is_nc; then
    emit trojan_removed 3 false "$TROJAN still behaves as netcat"
else
    emit trojan_removed 3 true ""
fi

# ---- 6. SUID plant cannot grant root (execute as non-root) ------------------
suid_bad=false
if [ -f "$SUID_PLANT" ]; then
    [ -u "$SUID_PLANT" ] && suid_bad=true
    if id "$ADMIN" >/dev/null 2>&1; then
        euid=$(su -s /bin/bash -c "\"$SUID_PLANT\" -p -c 'id -u'" "$ADMIN" 2>/dev/null | tr -d '[:space:]')
        [ "$euid" = "0" ] && suid_bad=true
    fi
fi
if $suid_bad; then
    emit suid_plant_fixed 3 false "$SUID_PLANT still privileged"
else
    emit suid_plant_fixed 3 true ""
fi

# ---- 7. backdoor listener silent (no socket + TCP connect refused) ---------
listener_open=false
ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ":${PORT}\$" && listener_open=true
if (exec 3<>/dev/tcp/127.0.0.1/${PORT}) 2>/dev/null; then
    listener_open=true
    exec 3<&- 3>&- 2>/dev/null
fi
if $listener_open; then
    emit backdoor_listener_silent 3 false "port $PORT reachable"
else
    emit backdoor_listener_silent 3 true ""
fi

# ---- 8. sshd PermitRootLogin no (effective + root ssh fails) ----------------
eff_prl=$(sshd_eff permitrootlogin)
root_blocked=true
ssh_probe root toor && root_blocked=false
ssh_probe root root && root_blocked=false
prl_ok=false
case "$eff_prl" in no|prohibit-password) prl_ok=true ;; esac
if $prl_ok && $root_blocked; then
    emit sshd_no_root 2 true ""
else
    emit sshd_no_root 2 false "PermitRootLogin=$eff_prl root_blocked=$root_blocked"
fi

# ---- 9. sshd PermitEmptyPasswords no (effective + empty pw fails) -----------
eff_pep=$(sshd_eff permitemptypasswords)
empty_blocked=true
ssh_probe "$ADMIN" "" && empty_blocked=false
if [ "$eff_pep" = "no" ] && $empty_blocked; then
    emit sshd_no_empty_pw 1 true ""
else
    emit sshd_no_empty_pw 1 false "PermitEmptyPasswords=$eff_pep empty_blocked=$empty_blocked"
fi

# ---- 10. new-user PASS_MAX_DAYS <=365 (behavioural useradd) -----------------
probe_user="hsprobe$$"
userdel -r "$probe_user" >/dev/null 2>&1
useradd -m -s /bin/bash "$probe_user" >/dev/null 2>&1
probe_max=$(chage -l "$probe_user" 2>/dev/null | awk -F: '/Maximum number of days/ {gsub(/[[:space:]]/,"",$2); print $2}')
userdel -r "$probe_user" >/dev/null 2>&1
if [ -n "$probe_max" ] && [ "$probe_max" != "never" ] && [ "$probe_max" -le 365 ] 2>/dev/null; then
    emit login_defs_maxdays 1 true ""
else
    emit login_defs_maxdays 1 false "new user PASS_MAX_DAYS=${probe_max:-unset}"
fi

# ---- 11. /etc/shadow perms tight (stat + non-root cannot read) --------------
mode=$(stat -c '%a' /etc/shadow)
nonroot_read=false
if id "$ADMIN" >/dev/null 2>&1; then
    if su -s /bin/bash -c 'cat /etc/shadow >/dev/null 2>&1' "$ADMIN"; then
        nonroot_read=true
    fi
fi
tight=false
case "$mode" in 600|640|000) tight=true ;; esac
if $tight && ! $nonroot_read; then
    emit shadow_perms 2 true ""
else
    emit shadow_perms 2 false "mode=$mode nonroot_read=$nonroot_read"
fi

# ---- 12. sysctl ip_forward (eff + live) -------------------------------------
e=$(eff_sysctl net.ipv4.ip_forward)
l=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
if [ "$e" = "0" ] && [ "$l" = "0" ]; then
    emit sysctl_ip_forward 1 true ""
else
    emit sysctl_ip_forward 1 false "eff=$e live=$l"
fi

# ---- 13. sysctl accept_redirects (eff + live) --------------------------------
e=$(eff_sysctl net.ipv4.conf.all.accept_redirects)
l=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
if [ "$e" = "0" ] && [ "$l" = "0" ]; then
    emit sysctl_accept_redirects 1 true ""
else
    emit sysctl_accept_redirects 1 false "eff=$e live=$l"
fi

# ---- 14. apache ServerTokens tightened (HTTP Server header) -----------------
srv_hdr=$(curl -sI --max-time 5 http://127.0.0.1/ 2>/dev/null | awk -F': ' 'tolower($1)=="server"{sub(/\r/,"",$2);print $2}')
if echo "$srv_hdr" | grep -Eq '^Apache[[:space:]]*$'; then
    emit apache_server_tokens 1 true ""
else
    emit apache_server_tokens 1 false "Server header='$srv_hdr'"
fi

# ---- 15. apache no Indexes for /var/www/html (HTTP behavioural) -------------
pd=".hsprobe$$"
mkdir -p "/var/www/html/$pd" 2>/dev/null
body=$(curl -s --max-time 5 "http://127.0.0.1/$pd/" 2>/dev/null)
rm -rf "/var/www/html/$pd"
if echo "$body" | grep -qi '<title>Index of'; then
    emit apache_no_indexes 1 false "autoindex still enabled"
else
    emit apache_no_indexes 1 true ""
fi

# ---- 16. PHP allow_url_include off (behavioural fetch) ----------------------
probe_php="/var/www/html/hsprobe$$.php"
printf '%s\n' '<?php echo "uai=" . ini_get("allow_url_include"); ?>' >"$probe_php"
body=$(curl -s --max-time 5 "http://127.0.0.1/hsprobe$$.php" 2>/dev/null)
rm -f "$probe_php"
if echo "$body" | grep -Eq 'uai=1'; then
    emit php_no_url_include 1 false "allow_url_include live=1"
elif echo "$body" | grep -q 'uai='; then
    emit php_no_url_include 1 true ""
else
    emit php_no_url_include 1 false "PHP probe unreachable"
fi

# ---- 17. mariadb not bound to public (live listening socket) ---------------
bad_bind=false
if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '^0\.0\.0\.0:3306$|^\*:3306$|^\[::\]:3306$'; then
    bad_bind=true
fi
if $bad_bind; then
    emit mariadb_bind_local 1 false "mysqld listens on public address"
else
    emit mariadb_bind_local 1 true ""
fi

# ---- service probes (weight=0, informational) -------------------------------
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
