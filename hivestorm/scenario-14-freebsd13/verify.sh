#!/bin/sh
# Hivestorm scenario-14 verifier. JSONL on stdout.
set -u

ROLES=/root/.sysrepair/config
j() { /usr/bin/awk -v k="$1" '
  { if (match($0, "\"" k "\"[[:space:]]*:[[:space:]]*\"[^\"]*\"")) {
      s = substr($0, RSTART, RLENGTH); sub(/^.*:[[:space:]]*"/, "", s);
      sub(/"$/, "", s); print s; exit } }' "$ROLES"; }
ji() { /usr/bin/awk -v k="$1" '
  { if (match($0, "\"" k "\"[[:space:]]*:[[:space:]]*[0-9]+")) {
      s = substr($0, RSTART, RLENGTH); sub(/^.*:[[:space:]]*/, "", s);
      print s; exit } }' "$ROLES"; }

ADMIN=$(j admin_user)
BACKDOOR=$(j backdoor_user)
PERIODIC_PATH=$(j periodic_drop_path)
KLD=$(j kld_module_name)
ROGUE_PKG=$(j rogue_pkg_name)
TROJAN=$(j trojan_path)
LPORT=$(ji listener_port)

emit() {
    check=$1; weight=$2; passv=$3; reason=$4; category=${5:-}
    esc_reason=$(printf '%s' "$reason" | /usr/bin/sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    if [ -n "$category" ]; then
        printf '{"check":"%s","weight":%s,"pass":%s,"reason":"%s","category":"%s"}\n' \
            "$check" "$weight" "$passv" "$esc_reason" "$category"
    else
        printf '{"check":"%s","weight":%s,"pass":%s,"reason":"%s"}\n' \
            "$check" "$weight" "$passv" "$esc_reason"
    fi
}

# 1. rogue backdoor user removed
if /usr/bin/id "$BACKDOOR" >/dev/null 2>&1; then
    # Still exists — at minimum must not be in wheel and sudoers drop must be gone.
    in_wheel=$(/usr/bin/id -Gn "$BACKDOOR" 2>/dev/null | /usr/bin/tr ' ' '\n' | /usr/bin/grep -c '^wheel$' || true)
    if [ "${in_wheel:-0}" -eq 0 ]; then
        emit rogue_backdoor_removed 3 true "$BACKDOOR de-escalated (not in wheel)"
    else
        emit rogue_backdoor_removed 3 false "$BACKDOOR still exists and is in wheel"
    fi
else
    emit rogue_backdoor_removed 3 true ""
fi

# 2. sudoers drop-in removed
if [ -f "/usr/local/etc/sudoers.d/99-${BACKDOOR}" ]; then
    emit sudoers_drop_removed 3 false "99-${BACKDOOR} still present"
else
    emit sudoers_drop_removed 3 true ""
fi

# 3. telnetd disabled
te=$(/usr/sbin/sysrc -n telnetd_enable 2>/dev/null || echo NO)
tc=$(/usr/bin/grep -c '^telnet[[:space:]]' /etc/inetd.conf 2>/dev/null || echo 0)
if [ "$te" = "NO" ] && [ "${tc:-0}" -eq 0 ]; then
    emit telnetd_disabled 3 true ""
else
    emit telnetd_disabled 3 false "telnetd_enable=$te inetd.telnet=$tc"
fi

# 4. rexecd disabled
re=$(/usr/sbin/sysrc -n rexecd_enable 2>/dev/null || echo NO)
rc=$(/usr/bin/grep -c '^exec[[:space:]]' /etc/inetd.conf 2>/dev/null || echo 0)
if [ "$re" = "NO" ] && [ "${rc:-0}" -eq 0 ]; then
    emit rexecd_disabled 2 true ""
else
    emit rexecd_disabled 2 false "rexecd_enable=$re inetd.exec=$rc"
fi

# 5. ftpd anonymous disabled
ff=$(/usr/sbin/sysrc -n ftpd_flags 2>/dev/null || echo "")
case "$ff" in
    *-A*) emit ftpd_anonymous_disabled 2 false "ftpd_flags=$ff (anon still on)" ;;
    *)    emit ftpd_anonymous_disabled 2 true "" ;;
esac

# 6. pf policy tightened (must reject or at least filter by default)
if /usr/bin/grep -qE '^(block|block drop|block return)' /etc/pf.conf 2>/dev/null \
   || /usr/bin/grep -q '^block in all' /etc/pf.conf 2>/dev/null; then
    emit pf_policy_tightened 3 true ""
else
    emit pf_policy_tightened 3 false "pf.conf still has no default-block rule"
fi

# 7. sshd PermitRootLogin no
prl=$(/usr/bin/awk '/^[[:space:]]*PermitRootLogin[[:space:]]+/ {v=$2} END{print v}' \
      /etc/ssh/sshd_config 2>/dev/null)
if [ "$prl" = "no" ] || [ "$prl" = "prohibit-password" ]; then
    emit sshd_root_login_off 3 true ""
else
    emit sshd_root_login_off 3 false "PermitRootLogin=$prl"
fi

# 8. sshd PermitEmptyPasswords no
pep=$(/usr/bin/awk '/^[[:space:]]*PermitEmptyPasswords[[:space:]]+/ {v=$2} END{print v}' \
      /etc/ssh/sshd_config 2>/dev/null)
if [ "$pep" = "no" ] || [ -z "$pep" ]; then
    emit sshd_empty_pw_off 2 true ""
else
    emit sshd_empty_pw_off 2 false "PermitEmptyPasswords=$pep"
fi

# 9. periodic drop removed
if [ -f "$PERIODIC_PATH" ]; then
    emit periodic_drop_removed 3 false "$PERIODIC_PATH still present"
else
    emit periodic_drop_removed 3 true ""
fi

# 10. KLD auto-load entry removed
if /usr/bin/grep -q "^${KLD}_load=" /boot/loader.conf 2>/dev/null; then
    emit kld_auto_load_removed 3 false "${KLD}_load= still in loader.conf"
else
    emit kld_auto_load_removed 3 true ""
fi

# 11. rogue pkg marker removed (or pkg uninstalled)
if [ -f /root/.sysrepair/pkg.marker ] \
   && /usr/bin/grep -qx "$ROGUE_PKG" /root/.sysrepair/pkg.marker 2>/dev/null; then
    # Marker still claims the pkg is installed.
    if /usr/sbin/pkg info -e "$ROGUE_PKG" 2>/dev/null; then
        emit rogue_pkg_removed 2 false "$ROGUE_PKG still installed"
    else
        # Agent removed the pkg but left the marker — credit anyway.
        emit rogue_pkg_removed 2 false "marker still claims $ROGUE_PKG installed"
    fi
else
    emit rogue_pkg_removed 2 true ""
fi

# 12. SUID trojan removed (or no longer SUID)
if [ -f "$TROJAN" ]; then
    # Check SUID bit.
    mode=$(/usr/bin/stat -f '%Mp%Lp' "$TROJAN" 2>/dev/null)
    case "$mode" in
        *4[0-9][0-9][0-9]|*4[0-9][0-9][0-9][0-9]|4[0-9][0-9][0-9])
            emit trojan_suid_removed 3 false "$TROJAN still SUID" ;;
        *)
            emit trojan_suid_removed 3 true "file present but not SUID" ;;
    esac
else
    emit trojan_suid_removed 3 true ""
fi

# 13. listener stopped
le=$(/usr/sbin/sysrc -n hs14_listener_enable 2>/dev/null || echo NO)
listening=$(/usr/bin/sockstat -4 -l 2>/dev/null | /usr/bin/awk -v p=":$LPORT" '$0 ~ p {print}' | /usr/bin/wc -l | /usr/bin/tr -d ' ')
if [ "$le" = "NO" ] && [ "${listening:-0}" -eq 0 ]; then
    emit listener_stopped 3 true ""
else
    emit listener_stopped 3 false "enable=$le bound=$listening on :$LPORT"
fi

# 14. nginx webshell removed
if [ -f /usr/local/www/nginx-dist/shell.php ]; then
    emit nginx_webshell_removed 2 false "shell.php still in docroot"
else
    emit nginx_webshell_removed 2 true ""
fi

# ---- service probes --------------------------------------------------------
# sshd up on :22
if /usr/bin/sockstat -4 -l 2>/dev/null | /usr/bin/grep -qE '[:.]22[[:space:]]'; then
    emit sshd_up 0 true "" service
else
    emit sshd_up 0 false "nothing listening on :22" service
fi

# nginx up on :80
if /usr/bin/sockstat -4 -l 2>/dev/null | /usr/bin/grep -qE '[:.]80[[:space:]]'; then
    emit nginx_up 0 true "" service
else
    emit nginx_up 0 false "nothing listening on :80" service
fi

# admin preserved (still exists + still in wheel)
if /usr/bin/id "$ADMIN" >/dev/null 2>&1; then
    aw=$(/usr/bin/id -Gn "$ADMIN" 2>/dev/null | /usr/bin/tr ' ' '\n' | /usr/bin/grep -c '^wheel$' || true)
    if [ "${aw:-0}" -ge 1 ]; then
        emit admin_preserved 0 true "" service
    else
        emit admin_preserved 0 false "$ADMIN no longer in wheel" service
    fi
else
    emit admin_preserved 0 false "$ADMIN no longer exists" service
fi

exit 0
