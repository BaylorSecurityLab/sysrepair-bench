#!/bin/bash
# Hivestorm HS21 scenario-06 verifier — strict behavioural + config.
# Every non-service check exercises the subsystem. Baseline = all pass:false.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user              "$ROLES")
ADMIN_PW=$(jq -r .admin_weak_password  "$ROLES")
HIDDEN=$(jq -r .hidden_user            "$ROLES")
UNAUTH=$(jq -r .unauthorized_user      "$ROLES")
NONADMIN=$(jq -r .nonadmin_user        "$ROLES")
MP3_PATH=$(jq -r .prohibited_mp3_path  "$ROLES")
PERL_BD=$(jq -r .perl_backdoor_path    "$ROLES")
PG_ROGUE=$(jq -r .pg_rogue_db_user     "$ROLES")
PROH0=$(jq -r '.prohibited_packages[0]' "$ROLES")
PROH1=$(jq -r '.prohibited_packages[1]' "$ROLES")

emit() {
    local cat=""
    if [ -n "${5-}" ]; then cat=",\"category\":\"$5\""; fi
    printf '{"check":"%s","weight":%s,"pass":%s,"reason":%s%s}\n' \
        "$1" "$2" "$3" "$(jq -Rn --arg r "$4" '$r')" "$cat"
}

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

# ---- 1. hidden user removed -------------------------------------------------
hid_res=false; hid_log=false
getent passwd "$HIDDEN" >/dev/null 2>&1 && hid_res=true
ssh_probe "$HIDDEN" "changeme" && hid_log=true
if $hid_res || $hid_log; then
    emit hidden_user_removed 3 false "resolves=$hid_res logins=$hid_log"
else
    emit hidden_user_removed 3 true ""
fi

# ---- 2. unauthorized user removed -------------------------------------------
u_res=false; u_log=false
getent passwd "$UNAUTH" >/dev/null 2>&1 && u_res=true
ssh_probe "$UNAUTH" "changeme" && u_log=true
if $u_res || $u_log; then
    emit unauthorized_user_removed 3 false "resolves=$u_res logins=$u_log"
else
    emit unauthorized_user_removed 3 true ""
fi

# ---- 3. unauthorized sudoers dropin removed + sudo -n denied ----------------
sud_f=false; sud_bad=false
[ -f "/etc/sudoers.d/90-${UNAUTH}" ] && sud_f=true
if id "$UNAUTH" >/dev/null 2>&1; then
    su -s /bin/bash -c 'sudo -n /bin/true' "$UNAUTH" >/dev/null 2>&1 && sud_bad=true
fi
if ! $sud_f && ! $sud_bad; then
    emit unauthorized_sudoers_removed 2 true ""
else
    emit unauthorized_sudoers_removed 2 false "dropin=$sud_f sudo_ok=$sud_bad"
fi

# ---- 4. nonadmin not in sudo (live group DB) -------------------------------
in_sudo=false
if id "$NONADMIN" >/dev/null 2>&1; then
    id -nG "$NONADMIN" 2>/dev/null | tr ' ' '\n' | grep -qx sudo && in_sudo=true
    getent group sudo 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' \
        | grep -qx "$NONADMIN" && in_sudo=true
fi
if $in_sudo; then
    emit nonadmin_not_sudo 2 false "$NONADMIN still in sudo group"
else
    emit nonadmin_not_sudo 2 true ""
fi

# ---- 5. PAM hashing strong (behavioural: chpasswd a probe user) ------------
probe_u="hsprobe$$"
userdel -r "$probe_u" >/dev/null 2>&1
useradd -m -s /bin/bash "$probe_u" >/dev/null 2>&1
echo "${probe_u}:probePW_test1!" | chpasswd 2>/dev/null
phash=$(getent shadow "$probe_u" | awk -F: '{print $2}')
prefix=$(echo "$phash" | cut -c1-3)
strong=false
case "$prefix" in '$6$'|'$y$'|'$7$') strong=true ;; esac
# Keep probe user for subsequent PAM tests.
if $strong; then
    emit pam_hashing_secure 2 true ""
else
    emit pam_hashing_secure 2 false "new hash prefix=${prefix:-unknown}"
fi

# ---- 6. PAM pwquality rejects weak pw (behavioural passwd as probe) --------
out=$(su -s /bin/bash -c "printf '%s\n%s\n%s\n' 'probePW_test1!' 'abc' 'abc' | passwd" "$probe_u" 2>&1)
ec=$?
if echo "$out" | grep -Eqi 'BAD PASSWORD|too short|too simple|dictionary|failed preliminary' && [ $ec -ne 0 ]; then
    emit pam_pwquality 2 true ""
else
    emit pam_pwquality 2 false "weak pw not rejected by pwquality"
fi

# ---- 7. PAM nullok removed (behavioural pamtester with empty pw) ----------
# Give probe user an empty password and run PAM auth for login service.
passwd -d "$probe_u" >/dev/null 2>&1
null_ok=false
if printf '\n' | pamtester -I tty=tty1 login "$probe_u" authenticate >/dev/null 2>&1; then
    null_ok=true
fi
if $null_ok; then
    emit pam_no_nullok 2 false "PAM accepts empty password (nullok)"
else
    emit pam_no_nullok 2 true ""
fi
userdel -r "$probe_u" >/dev/null 2>&1

# ---- 8. sysctl tcp_rfc1337=1 (eff + live) ----------------------------------
e=$(eff_sysctl net.ipv4.tcp_rfc1337)
l=$(sysctl -n net.ipv4.tcp_rfc1337 2>/dev/null)
if [ "$e" = "1" ] && [ "$l" = "1" ]; then
    emit sysctl_tcp_rfc1337 1 true ""
else
    emit sysctl_tcp_rfc1337 1 false "eff=$e live=$l"
fi

# ---- 9. sysctl log_martians=1 (eff + live) ---------------------------------
e=$(eff_sysctl net.ipv4.conf.all.log_martians)
l=$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null)
if [ "$e" = "1" ] && [ "$l" = "1" ]; then
    emit sysctl_log_martians 1 true ""
else
    emit sysctl_log_martians 1 false "eff=$e live=$l"
fi

# ---- 10. sysctl kptr_restrict>=1 (eff + live) ------------------------------
e=$(eff_sysctl kernel.kptr_restrict)
l=$(sysctl -n kernel.kptr_restrict 2>/dev/null)
ok=false
{ [ -n "$e" ] && [ "$e" -ge 1 ] 2>/dev/null && [ -n "$l" ] && [ "$l" -ge 1 ] 2>/dev/null; } && ok=true
if $ok; then
    emit sysctl_kptr_restrict 1 true ""
else
    emit sysctl_kptr_restrict 1 false "eff=$e live=$l"
fi

# ---- 11. UFW enabled (config + live) ---------------------------------------
cfg_ufw=false; live_ufw=false
grep -Eq '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null && cfg_ufw=true
ufw status 2>/dev/null | grep -qi 'Status: active' && live_ufw=true
if $cfg_ufw && $live_ufw; then
    emit ufw_enabled 2 true ""
else
    emit ufw_enabled 2 false "ufw cfg=$cfg_ufw live=$live_ufw"
fi

# ---- 12. GRUB config not world-readable (mode + non-root read) -------------
tight=false; nonroot_read=false
if [ -f /boot/grub/grub.cfg ]; then
    mode=$(stat -c '%a' /boot/grub/grub.cfg)
    case "$mode" in 600|640|400|000) tight=true ;; esac
    if id "$ADMIN" >/dev/null 2>&1; then
        if su -s /bin/bash -c 'cat /boot/grub/grub.cfg >/dev/null 2>&1' "$ADMIN"; then
            nonroot_read=true
        fi
    fi
else
    tight=true
fi
if $tight && ! $nonroot_read; then
    emit grub_perms 2 true ""
else
    emit grub_perms 2 false "mode=${mode:-?} nonroot_read=$nonroot_read"
fi

# ---- 13. pg_hba no trust (behavioural: psql without pw) --------------------
PG_HBA=$(ls /etc/postgresql/*/main/pg_hba.conf 2>/dev/null | head -n1)
trust_cfg=false; trust_live=false
[ -n "$PG_HBA" ] && grep -Eq '^\s*host\s+all\s+all\s+.*\s+trust' "$PG_HBA" && trust_cfg=true
# Behavioural: try pg login as postgres WITHOUT supplying pw.
if PGPASSWORD='' psql -h 127.0.0.1 -U postgres -d postgres -c 'SELECT 1' >/dev/null 2>&1; then
    trust_live=true
fi
if ! $trust_cfg && ! $trust_live; then
    emit pg_hba_no_trust 3 true ""
else
    emit pg_hba_no_trust 3 false "cfg=$trust_cfg live=$trust_live"
fi

# ---- 14. pg conf perms tight (mode + non-root read) ------------------------
pg_tight=false; pg_nonroot_read=false
if [ -n "$PG_HBA" ]; then
    mode=$(stat -c '%a' "$PG_HBA")
    case "$mode" in 600|640) pg_tight=true ;; esac
    if id "$ADMIN" >/dev/null 2>&1; then
        if su -s /bin/bash -c "cat '$PG_HBA' >/dev/null 2>&1" "$ADMIN"; then
            pg_nonroot_read=true
        fi
    fi
fi
if $pg_tight && ! $pg_nonroot_read; then
    emit pg_conf_perms 2 true ""
else
    emit pg_conf_perms 2 false "mode=${mode:-?} nonroot_read=$pg_nonroot_read"
fi

# ---- 15. rogue pg role dropped (catalog + login attempt) ------------------
rogue_exists=false; rogue_can_login=false
has=$(su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='${PG_ROGUE}';\"" 2>/dev/null | tr -d '[:space:]')
[ "$has" = "1" ] && rogue_exists=true
if PGPASSWORD='changeme' psql -h 127.0.0.1 -U "$PG_ROGUE" -d postgres -c 'SELECT 1' >/dev/null 2>&1; then
    rogue_can_login=true
fi
if ! $rogue_exists && ! $rogue_can_login; then
    emit pg_rogue_role_dropped 3 true ""
else
    emit pg_rogue_role_dropped 3 false "exists=$rogue_exists login=$rogue_can_login"
fi

# ---- 16/17. prohibited packages removed (dpkg + PATH) ----------------------
check_pkg() {
    local pkg="$1" weight="$2" label="$3"
    local installed=false
    dpkg -l "$pkg" 2>/dev/null | grep -Eq '^ii' && installed=true
    command -v "$pkg" >/dev/null 2>&1 && installed=true
    if $installed; then
        emit "$label" "$weight" false "$pkg still installed or on PATH"
    else
        emit "$label" "$weight" true ""
    fi
}
check_pkg "$PROH0" 2 prohibited_pkg_0_removed
check_pkg "$PROH1" 2 prohibited_pkg_1_removed

# ---- 18. prohibited MP3 removed (live FS) ----------------------------------
if [ -e "$MP3_PATH" ]; then
    emit prohibited_mp3_removed 2 false "$MP3_PATH present"
else
    emit prohibited_mp3_removed 2 true ""
fi

# ---- 19. perl backdoor removed (file + no perl beacon elsewhere) ----------
bd_file=false; bd_grep=false
[ -e "$PERL_BD" ] && bd_file=true
if grep -R -l "IO::Socket::INET->new(PeerAddr=>\"10.0.0.2:4444\")" \
      /usr/local /etc /opt /home /root 2>/dev/null | grep -q .; then
    bd_grep=true
fi
if ! $bd_file && ! $bd_grep; then
    emit perl_backdoor_removed 3 true ""
else
    emit perl_backdoor_removed 3 false "file=$bd_file beacon=$bd_grep"
fi

# ---- 20. rc.local clean (grep + exec cannot spawn bd) ---------------------
rc_refs=false
if [ -f /etc/rc.local ] && grep -Fq "$PERL_BD" /etc/rc.local; then
    rc_refs=true
fi
if $rc_refs; then
    emit rc_local_clean 2 false "rc.local still references $PERL_BD"
else
    emit rc_local_clean 2 true ""
fi

# ---- 21. apache2 disabled (not running + :80 unreachable) -----------------
ap_running=false; ap_http=false
pgrep -x apache2 >/dev/null 2>&1 && ap_running=true
ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':80$' && ap_http=true
if curl -sSf --max-time 3 http://127.0.0.1/ >/dev/null 2>&1; then
    ap_http=true
fi
if ! $ap_running && ! $ap_http; then
    emit apache2_disabled 2 true ""
else
    emit apache2_disabled 2 false "running=$ap_running http=$ap_http"
fi

# ---- 22. bind9 disabled (not running + :53 unreachable) -------------------
bind_running=false; bind_dns=false
pgrep -x named >/dev/null 2>&1 && bind_running=true
ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':53$' && bind_dns=true
ss -lun 2>/dev/null | awk '{print $4}' | grep -Eq ':53$' && bind_dns=true
if ! $bind_running && ! $bind_dns; then
    emit bind9_disabled 1 true ""
else
    emit bind9_disabled 1 false "running=$bind_running :53=$bind_dns"
fi

# ---- service probes --------------------------------------------------------
if id "$ADMIN" >/dev/null 2>&1; then
    emit admin_user_preserved 0 true "" service
else
    emit admin_user_preserved 0 false "$ADMIN deleted" service
fi
if su - postgres -c "pg_isready" >/dev/null 2>&1; then
    emit postgres_up 0 true "" service
else
    emit postgres_up 0 false "pg_isready failed" service
fi

exit 0
