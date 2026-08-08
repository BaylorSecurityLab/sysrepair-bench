#!/bin/sh
# Hivestorm scenario-14 verifier. JSONL on stdout.
set -u

# Two-component verdict protocol -- see lib/verifylib.sh. Purely ADDITIVE here:
# the weighted {"check":...} JSONL below is untouched and still drives
# hivestorm's partial credit, because the library's records carry neither
# "weight" nor "category" and so contribute 0 to both the numerator and the
# denominator in _score_hivestorm. What they add is the security/regression
# decomposition, which a single weighted total cannot express.
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
#
# FreeBSD note: the scorer runs this file as `sudo sh /tmp/verify.sh`, so both
# this file and the library execute under FreeBSD's ash-derived /bin/sh, not
# bash. NOTHING BELOW MAY USE A BASHISM. This used to matter for the library
# too: _sr_json_escape used ${v//a/b}, which those shells reject at expansion
# time ("Bad substitution"), killing the $( ) subshell and emitting records
# whose id and detail were empty. lib/verifylib.sh now selects a POSIX
# tr+sed implementation when BASH_VERSION is unset, so the records come out
# fully populated here; the note is kept because the constraint on THIS file is
# unchanged.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# No tamper guard here, unlike the Linux hivestorm verifiers: if $ROLES is
# absent or unreadable the j()/ji() awk readers simply yield empty strings and
# the identity checks below evaluate against them. That is this scenario's
# existing behaviour and it is left exactly as it was -- adding a guard would be
# a new check, not a change to how outcomes are reported.
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

    # Mirror the SAME booleans into the two-component protocol. Routing both
    # views through one call site means they can never disagree, and no check
    # can be migrated by accident or left behind.
    #
    # Kind assignment follows this file's own taxonomy, not a fresh judgement:
    # category=service checks assert the box still does its job (sshd on :22,
    # nginx on :80, the admin still in wheel) and therefore hold on an untouched
    # vulnerable box -- that is the regression component. Every weighted check
    # asserts an attack path is closed, which is the PoC component.
    if [ "$passv" = "true" ]; then sr_ok=1; else sr_ok=0; fi
    if [ "$category" = "service" ]; then
        record_reg "$check" "$sr_ok" "$reason"
    else
        record_poc "$check" "$sr_ok" "$reason"
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
#
# COUNTING IDIOM -- do not revert this to `|| echo 0`. `grep -c` prints the
# count (0) on stdout AND exits 1 when the file EXISTS but holds no match, so
# `$(grep -c ... || echo 0)` captured grep's own "0" and then appended a second
# one: tc became the two-line string "0\n0", and `[ "$tc" -eq 0 ]` died with
# "illegal number" -- non-zero status, so the test was false and the emit went
# down the FALSE arm. A real FreeBSD box ships /etc/inetd.conf, so telnetd_disabled
# and rexecd_disabled below could NEVER pass there no matter how the box was
# remediated: two unsolvable checks pinning the oracle ceiling below 100%.
# `x=$(cmd) || x=0` sets the fallback INSTEAD of appending to the output; the
# case arm then rejects anything that is not a plain decimal, so no future
# stdout surprise can reach the arithmetic test.
te=$(/usr/sbin/sysrc -n telnetd_enable 2>/dev/null || echo NO)
tc=$(/usr/bin/grep -c '^telnet[[:space:]]' /etc/inetd.conf 2>/dev/null) || tc=0
case "$tc" in ''|*[!0-9]*) tc=0 ;; esac
if [ "$te" = "NO" ] && [ "${tc:-0}" -eq 0 ]; then
    emit telnetd_disabled 3 true ""
else
    emit telnetd_disabled 3 false "telnetd_enable=$te inetd.telnet=$tc"
fi

# 4. rexecd disabled
# Same counting idiom as check 3 above, same reason.
re=$(/usr/sbin/sysrc -n rexecd_enable 2>/dev/null || echo NO)
rc=$(/usr/bin/grep -c '^exec[[:space:]]' /etc/inetd.conf 2>/dev/null) || rc=0
case "$rc" in ''|*[!0-9]*) rc=0 ;; esac
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

verify_finish
