#!/bin/bash
# Hivestorm HS23 scenario-10 — Ubuntu 22.04 + faillock + group hygiene.
set -euo pipefail

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user             "$ROLES")
ADMINPW=$(jq -r .admin_weak_password  "$ROLES")
HIDDEN=$(jq -r .hidden_user           "$ROLES")
NONADMIN=$(jq -r .nonadmin_user       "$ROLES")
PROH_PKG=$(jq -r .prohibited_package  "$ROLES")
MP3_PATH=$(jq -r .prohibited_mp3_path "$ROLES")

# ---- users -------------------------------------------------------------------
useradd -m -s /bin/bash "$ADMIN"
echo "${ADMIN}:${ADMINPW}" | chpasswd
usermod -aG sudo "$ADMIN"

useradd -m -s /bin/bash "$HIDDEN"
echo "${HIDDEN}:hidden123" | chpasswd

useradd -m -s /bin/bash "$NONADMIN"
echo "${NONADMIN}:weakpw1" | chpasswd
usermod -aG sudo "$NONADMIN"

# Create the four "remote" group members (randomized) but DO NOT create the
# remote group itself — agent must create it and add exactly these four.
for u in $(jq -r '.remote_group_users[]' "$ROLES"); do
    useradd -m -s /bin/bash "$u"
    echo "${u}:weakpw2" | chpasswd
done

# ---- PAM: pam_faillock not configured ---------------------------------------
# Strip any existing pam_faillock lines so check fails by default.
sed -ri '/pam_faillock\.so/d' /etc/pam.d/common-auth || true

# ---- PAM: pam_unix downgraded to md5 ----------------------------------------
sed -ri 's/(pam_unix\.so[^#]*\b)(yescrypt|sha512)\b/\1md5/g' \
    /etc/pam.d/common-password || true
if ! grep -Eq 'pam_unix\.so.*\b(md5|yescrypt|sha512)\b' /etc/pam.d/common-password; then
    sed -ri 's|^(password.*pam_unix\.so.*)$|\1 md5|' /etc/pam.d/common-password
fi

# ---- SSH ---------------------------------------------------------------------
sed -ri 's|^#?PermitRootLogin.*|PermitRootLogin yes|'      /etc/ssh/sshd_config
sed -ri 's|^#?PubkeyAuthentication.*|PubkeyAuthentication no|' /etc/ssh/sshd_config

# ---- UFW disabled ------------------------------------------------------------
mkdir -p /etc/ufw
cat > /etc/ufw/ufw.conf <<'EOF'
ENABLED=no
LOGLEVEL=low
EOF

# ---- sysctl: syncookies off --------------------------------------------------
cat > /etc/sysctl.d/99-hs23.conf <<'EOF'
net.ipv4.tcp_syncookies = 0
EOF

# ---- prohibited mp3 ----------------------------------------------------------
mkdir -p "$(dirname "$MP3_PATH")"
dd if=/dev/zero of="$MP3_PATH" bs=1k count=4 status=none
chown "${NONADMIN}:${NONADMIN}" "$MP3_PATH" || true

# Note: $PROH_PKG is installed via Dockerfile RUN apt-get install — agent must
# remove it. seed.sh doesn't need to do anything extra.
true
