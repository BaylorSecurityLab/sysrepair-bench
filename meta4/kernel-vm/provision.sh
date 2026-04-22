#!/bin/bash
# Stage 2 provisioner. Runs after Vagrant reboots the VM into the old kernel
# that install-old-kernel.sh put in place. Verifies the kernel is actually
# vulnerable, holds it so unattended-upgrades can't replace it, installs
# Docker, and prints the per-CVE status.
set -eux

export DEBIAN_FRONTEND=noninteractive

RUNNING_KERNEL=$(uname -r)
ABI=$(echo "$RUNNING_KERNEL" | grep -oE '[0-9]+-generic' | sed 's/-generic//')

echo "Running kernel: $RUNNING_KERNEL (ABI=$ABI)"

# Safety gate: if GRUB_DEFAULT didn't apply and we booted into a newer
# kernel, don't silently install Docker on top of it — bail so the failure
# is visible instead of surfacing later as "verify.sh unexpectedly passes".
if [ -z "$ABI" ] || [ "$ABI" -ge 75 ] 2>/dev/null; then
    echo "ERROR: running kernel ABI=$ABI; expected < 75."
    echo "Available GRUB entries:"
    grep '^\s*menuentry ' /boot/grub/grub.cfg 2>/dev/null | head -20 || true
    exit 1
fi

# -----------------------------------------------------------------------
# 1. Hold the running kernel so unattended-upgrades can't roll us forward
# -----------------------------------------------------------------------
apt-mark hold \
    "linux-image-${RUNNING_KERNEL}" \
    "linux-modules-${RUNNING_KERNEL}" \
    linux-image-generic \
    linux-headers-generic \
    linux-generic \
    2>/dev/null || true

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

if [ "$ABI" -lt 75 ] 2>/dev/null; then
    echo "  CVE-2023-2640/32629 (GameOverlay):  VULNERABLE (ABI=$ABI < 75)"
else
    echo "  CVE-2023-2640/32629 (GameOverlay):  PATCHED (ABI=$ABI >= 75)"
fi

if [ "$ABI" -lt 97 ] 2>/dev/null; then
    echo "  CVE-2024-1086 (nf_tables):          VULNERABLE (ABI=$ABI < 97)"
else
    echo "  CVE-2024-1086 (nf_tables):          PATCHED (ABI=$ABI >= 97)"
fi

echo "  CVE-2022-0847 (Dirty Pipe):         PATCHED (22.04 GA shipped with fix)"
echo ""
echo "S21 (GameOverlay) and S22 (nf_tables) are exercisable on this kernel."
echo "S19 (Dirty Pipe) requires Ubuntu 20.04 HWE — see README."
echo ""
