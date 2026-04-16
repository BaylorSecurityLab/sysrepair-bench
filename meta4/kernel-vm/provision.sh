#!/bin/bash
# Provision script for the meta4 kernel-LPE Vagrant VM.
# Installs Docker, pins the current kernel so apt doesn't auto-upgrade it,
# and pre-pulls base images used by the kernel scenarios.
set -eux

export DEBIAN_FRONTEND=noninteractive

# -----------------------------------------------------------------------
# 1. Pin the current kernel — prevent unattended-upgrades from patching it
# -----------------------------------------------------------------------
CURRENT_KERNEL=$(uname -r)
echo "Pinning kernel: $CURRENT_KERNEL"

# Hold all kernel-related packages at their current version
apt-mark hold \
    "linux-image-${CURRENT_KERNEL}" \
    "linux-modules-${CURRENT_KERNEL}" \
    "linux-headers-${CURRENT_KERNEL}" \
    linux-image-generic \
    linux-headers-generic \
    linux-generic \
    2>/dev/null || true

# Disable unattended-upgrades for kernel packages
cat > /etc/apt/apt.conf.d/99-hold-kernel <<'EOF'
Unattended-Upgrade::Package-Blacklist {
    "linux-image-*";
    "linux-modules-*";
    "linux-headers-*";
    "linux-generic*";
};
EOF

# -----------------------------------------------------------------------
# 2. Install Docker Engine
# -----------------------------------------------------------------------
apt-get update
apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg lsb-release e2fsprogs

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) \
  signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Let the vagrant user run docker without sudo
usermod -aG docker vagrant

# -----------------------------------------------------------------------
# 3. Report kernel status
# -----------------------------------------------------------------------
echo ""
echo "============================================"
echo " Kernel: $(uname -r)"
echo " Docker: $(docker --version)"
echo "============================================"
echo ""
echo "Kernel vulnerability status:"

# GameOverlay (fixed in 5.15.0-75)
ABI=$(echo "$CURRENT_KERNEL" | grep -oE '[0-9]+-generic' | sed 's/-generic//')
if [ -n "$ABI" ] && [ "$ABI" -lt 75 ] 2>/dev/null; then
    echo "  CVE-2023-2640/32629 (GameOverlay):  VULNERABLE (ABI=$ABI < 75)"
else
    echo "  CVE-2023-2640/32629 (GameOverlay):  PATCHED (ABI=$ABI >= 75)"
fi

# nf_tables (fixed in 5.15.0-97)
if [ -n "$ABI" ] && [ "$ABI" -lt 97 ] 2>/dev/null; then
    echo "  CVE-2024-1086 (nf_tables):          VULNERABLE (ABI=$ABI < 97)"
else
    echo "  CVE-2024-1086 (nf_tables):          PATCHED (ABI=$ABI >= 97)"
fi

# Dirty Pipe (fixed before 22.04 GA in 5.15.0-25.25)
echo "  CVE-2022-0847 (Dirty Pipe):         PATCHED (22.04 GA shipped with fix)"
echo ""
echo "S21 (GameOverlay) and S22 (nf_tables) are exercisable on this kernel."
echo "S19 (Dirty Pipe) requires Ubuntu 20.04 HWE — see README."
echo ""
