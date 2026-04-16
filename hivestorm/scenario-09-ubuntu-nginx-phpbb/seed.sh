#!/bin/bash
# Hivestorm HS23 scenario-09 — Ubuntu 20.04 + nginx + phpbb + persistence.
set -euo pipefail

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user                "$ROLES")
ADMINPW=$(jq -r .admin_weak_password     "$ROLES")
HIDDEN=$(jq -r .hidden_user              "$ROLES")
UNAUTH=$(jq -r .unauthorized_user        "$ROLES")
NONADMIN=$(jq -r .nonadmin_user          "$ROLES")
PROH_PKG=$(jq -r .prohibited_package     "$ROLES")
PROH_BIN=$(jq -r .prohibited_binary_path "$ROLES")
MP3_PATH=$(jq -r .prohibited_mp3_path    "$ROLES")
WEB_DROP=$(jq -r .webroot_drop_path      "$ROLES")
RUBY_UNIT=$(jq -r .ruby_unit_name        "$ROLES")
RUBY_PATH=$(jq -r .ruby_unit_path        "$ROLES")
SOCAT_BIN=$(jq -r .socat_trojan_path     "$ROLES")
SOCAT_CRON=$(jq -r .socat_cron_path      "$ROLES")

# ---- users -------------------------------------------------------------------
useradd -m -s /bin/bash "$ADMIN"
echo "${ADMIN}:${ADMINPW}" | chpasswd
usermod -aG sudo "$ADMIN"

useradd -m -s /bin/bash "$HIDDEN"
echo "${HIDDEN}:hidden123" | chpasswd

useradd -m -s /bin/bash "$UNAUTH"
echo "${UNAUTH}:changeme" | chpasswd
usermod -aG sudo "$UNAUTH"
echo "${UNAUTH} ALL=(ALL) NOPASSWD: ALL" > "/etc/sudoers.d/90-${UNAUTH}"
chmod 0440 "/etc/sudoers.d/90-${UNAUTH}"

useradd -m -s /bin/bash "$NONADMIN"
echo "${NONADMIN}:weakpw1" | chpasswd
usermod -aG sudo "$NONADMIN"

# ---- sudoers !authenticate ---------------------------------------------------
echo "Defaults !authenticate" >> /etc/sudoers

# ---- PAM weakened to md5 -----------------------------------------------------
sed -ri 's/(pam_unix\.so[^#]*\b)(yescrypt|sha512)\b/\1md5/g' \
    /etc/pam.d/common-password || true
if ! grep -q 'md5' /etc/pam.d/common-password; then
    sed -ri 's|^(password.*pam_unix\.so.*)$|\1 md5|' /etc/pam.d/common-password
fi
# strip pwquality so gecoscheck check has something to fail
sed -ri 's|^(password.*pam_pwquality.*)$|# \1|' /etc/pam.d/common-password || true

# ---- sysctl ------------------------------------------------------------------
cat > /etc/sysctl.d/99-hs23.conf <<'EOF'
net.ipv4.tcp_synack_retries = 5
kernel.kptr_restrict = 0
EOF

# ---- UFW disabled (default state — ensure conf says disabled) ---------------
mkdir -p /etc/ufw
cat > /etc/ufw/ufw.conf <<'EOF'
ENABLED=no
LOGLEVEL=low
EOF

# ---- nginx misconfig ---------------------------------------------------------
# Replace stock config with one that omits security headers + leaks tokens.
cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
events { worker_connections 768; }
http {
    server_tokens on;
    sendfile on;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    error_log  /var/log/nginx/error.log;

    server {
        listen 80 default_server;
        root /var/www/html;
        index index.html;
        location / {
            try_files $uri $uri/ =404;
        }
    }
}
EOF
mkdir -p /var/www/html
echo "<h1>Hivestorm HS23 stand-in</h1>" > /var/www/html/index.html

# ---- mock mysql config -------------------------------------------------------
mkdir -p /etc/mysql/mysql.conf.d
cat > /etc/mysql/my.cnf <<'EOF'
# Hivestorm-planted my.cnf (mysql daemon NOT actually installed; scoring
# targets file state).
[mysqld]
bind_address = 0.0.0.0
skip_name_resolve
EOF

# ---- SSH ---------------------------------------------------------------------
mkdir -p /etc/ssh
sed -ri 's|^#?PermitRootLogin.*|PermitRootLogin yes|' /etc/ssh/sshd_config 2>/dev/null \
    || echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# ---- phpbb webroot drop ------------------------------------------------------
mkdir -p "$(dirname "$WEB_DROP")"
cat > "$WEB_DROP" <<'EOF'
<!-- planted phpbb backup artifact -->
<html><body>backup data leak</body></html>
EOF

# ---- prohibited mp3 ----------------------------------------------------------
mkdir -p "$(dirname "$MP3_PATH")"
dd if=/dev/zero of="$MP3_PATH" bs=1k count=4 status=none

# ---- prohibited binary plant ($PROH_PKG installed via Dockerfile already) --
cp /bin/cat "$PROH_BIN"
chmod 0755 "$PROH_BIN"

# ---- ruby systemd unit (file-state only; container has no systemd) --------
mkdir -p "$(dirname "$RUBY_PATH")"
cat > "$RUBY_PATH" <<EOF
[Unit]
Description=Hivestorm-planted ruby backdoor (${RUBY_UNIT})
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ruby -e "while true do sleep 60 end"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# ---- socat trojan + cron persistence ---------------------------------------
cp /bin/cat "$SOCAT_BIN"
chmod 0755 "$SOCAT_BIN"

cat > "$SOCAT_CRON" <<EOF
# Hivestorm-planted cron persistence
* * * * * root ${SOCAT_BIN} >/dev/null 2>&1
EOF
chmod 0644 "$SOCAT_CRON"
