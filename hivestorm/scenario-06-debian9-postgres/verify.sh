#!/bin/bash
# Hivestorm HS21 scenario-06 verifier. JSONL on stdout. Never short-circuits.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user             "$ROLES")
HIDDEN=$(jq -r .hidden_user           "$ROLES")
UNAUTH=$(jq -r .unauthorized_user     "$ROLES")
NONADMIN=$(jq -r .nonadmin_user       "$ROLES")
MP3_PATH=$(jq -r .prohibited_mp3_path "$ROLES")
PERL_BD=$(jq -r .perl_backdoor_path   "$ROLES")
PG_ROGUE=$(jq -r .pg_rogue_db_user    "$ROLES")
PROH0=$(jq -r '.prohibited_packages[0]' "$ROLES")
PROH1=$(jq -r '.prohibited_packages[1]' "$ROLES")

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

# 3. unauthorized user's sudoers drop-in removed
if [ -f "/etc/sudoers.d/90-${UNAUTH}" ]; then
    emit unauthorized_sudoers_removed 2 false "drop-in present"
else
    emit unauthorized_sudoers_removed 2 true ""
fi

# 4. legit non-admin user stripped from sudo group
if id "$NONADMIN" >/dev/null 2>&1 && id -nG "$NONADMIN" | tr ' ' '\n' | grep -qx sudo; then
    emit nonadmin_not_sudo 2 false "$NONADMIN still in sudo"
else
    emit nonadmin_not_sudo 2 true ""
fi

# 5. PAM hashing: sha512 (or yescrypt) required, md5 gone
if grep -REq '\b(sha512|yescrypt)\b' /etc/pam.d/common-password 2>/dev/null \
 && ! grep -REq '\bmd5\b' /etc/pam.d/common-password 2>/dev/null; then
    emit pam_hashing_secure 2 true ""
else
    emit pam_hashing_secure 2 false "md5 still present or sha512 missing"
fi

# 6. PAM pwquality / minlen
if grep -REq '(pam_pwquality|pam_cracklib).*minlen=([89]|1[0-9]+)' /etc/pam.d/ 2>/dev/null; then
    emit pam_pwquality 2 true ""
else
    emit pam_pwquality 2 false "no minlen>=8 via pwquality"
fi

# 7. PAM null passwords disabled
if grep -Eq 'pam_unix\.so.*nullok' /etc/pam.d/common-auth 2>/dev/null; then
    emit pam_no_nullok 2 false "nullok still set"
else
    emit pam_no_nullok 2 true ""
fi

# 8. sysctl tcp_rfc1337=1
if [ "$(sysctl -n net.ipv4.tcp_rfc1337 2>/dev/null)" = "1" ]; then
    emit sysctl_tcp_rfc1337 1 true ""
else
    emit sysctl_tcp_rfc1337 1 false "tcp_rfc1337 off"
fi

# 9. sysctl log_martians=1
if [ "$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null)" = "1" ]; then
    emit sysctl_log_martians 1 true ""
else
    emit sysctl_log_martians 1 false "log_martians off"
fi

# 10. sysctl kptr_restrict>=1
K=$(sysctl -n kernel.kptr_restrict 2>/dev/null)
if [ -n "$K" ] && [ "$K" -ge 1 ] 2>/dev/null; then
    emit sysctl_kptr_restrict 1 true ""
else
    emit sysctl_kptr_restrict 1 false "kptr_restrict=${K:-unset}"
fi

# 11. UFW enabled
if ufw status 2>/dev/null | grep -qi 'Status: active'; then
    emit ufw_enabled 2 true ""
else
    emit ufw_enabled 2 false "ufw inactive"
fi

# 12. GRUB config not world-readable
if [ -f /boot/grub/grub.cfg ]; then
    MODE=$(stat -c '%a' /boot/grub/grub.cfg)
    if [ "$MODE" = "600" ] || [ "$MODE" = "640" ] || [ "$MODE" = "400" ]; then
        emit grub_perms 2 true ""
    else
        emit grub_perms 2 false "grub.cfg mode=$MODE"
    fi
else
    emit grub_perms 2 true "grub.cfg removed"
fi

# 13. pg_hba trust line removed + perms tightened
PG_HBA=$(ls /etc/postgresql/*/main/pg_hba.conf 2>/dev/null | head -n1)
if [ -n "$PG_HBA" ] && grep -Eq '^\s*host\s+all\s+all\s+0\.0\.0\.0/0\s+trust' "$PG_HBA"; then
    emit pg_hba_no_trust 3 false "trust line still present"
else
    emit pg_hba_no_trust 3 true ""
fi
if [ -n "$PG_HBA" ]; then
    MODE=$(stat -c '%a' "$PG_HBA")
    if [ "$MODE" = "640" ] || [ "$MODE" = "600" ]; then
        emit pg_conf_perms 2 true ""
    else
        emit pg_conf_perms 2 false "pg_hba mode=$MODE"
    fi
else
    emit pg_conf_perms 2 false "pg_hba.conf missing"
fi

# 14. rogue PG role dropped (check if role exists)
HAS_ROGUE=$(su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='${PG_ROGUE}';\"" 2>/dev/null)
if [ "$HAS_ROGUE" = "1" ]; then
    emit pg_rogue_role_dropped 3 false "$PG_ROGUE role exists"
else
    emit pg_rogue_role_dropped 3 true ""
fi

# 15. prohibited packages removed
if dpkg -l "$PROH0" 2>/dev/null | grep -Eq '^ii'; then
    emit prohibited_pkg_0_removed 2 false "$PROH0 still installed"
else
    emit prohibited_pkg_0_removed 2 true ""
fi
if dpkg -l "$PROH1" 2>/dev/null | grep -Eq '^ii'; then
    emit prohibited_pkg_1_removed 2 false "$PROH1 still installed"
else
    emit prohibited_pkg_1_removed 2 true ""
fi

# 16. prohibited MP3 removed
if [ -f "$MP3_PATH" ]; then
    emit prohibited_mp3_removed 2 false "$MP3_PATH present"
else
    emit prohibited_mp3_removed 2 true ""
fi

# 17. perl owl-shell backdoor removed
if [ -f "$PERL_BD" ]; then
    emit perl_backdoor_removed 3 false "$PERL_BD present"
else
    emit perl_backdoor_removed 3 true ""
fi

# 18. rc.local no longer launches the backdoor
if [ -f /etc/rc.local ] && grep -Fq "$PERL_BD" /etc/rc.local; then
    emit rc_local_clean 2 false "rc.local still references $PERL_BD"
else
    emit rc_local_clean 2 true ""
fi

# 19. apache2 disabled/removed (unneeded)
if dpkg -l apache2 2>/dev/null | grep -Eq '^ii'; then
    if pgrep -x apache2 >/dev/null 2>&1; then
        emit apache2_disabled 2 false "apache2 running"
    else
        emit apache2_disabled 2 true ""
    fi
else
    emit apache2_disabled 2 true "apache2 removed"
fi

# 20. bind9 disabled/removed
if dpkg -l bind9 2>/dev/null | grep -Eq '^ii'; then
    if pgrep -x named >/dev/null 2>&1; then
        emit bind9_disabled 1 false "named running"
    else
        emit bind9_disabled 1 true ""
    fi
else
    emit bind9_disabled 1 true "bind9 removed"
fi

# ---- service probes ----------------------------------------------------------
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
