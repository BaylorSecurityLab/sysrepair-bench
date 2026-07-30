#!/bin/bash
# Stage 2 for the Dirty Pipe VM. Runs after the reboot into 5.13.0-27. Verifies
# the running kernel is actually vulnerable, holds it so unattended-upgrades
# cannot roll it forward, and installs Docker.
set -eux

export DEBIAN_FRONTEND=noninteractive

RUNNING_KERNEL=$(uname -r)
ABI=$(echo "$RUNNING_KERNEL" | grep -oE '[0-9]+-generic' | sed 's/-generic//')

echo "Running kernel: $RUNNING_KERNEL (ABI=$ABI)"

# Safety gate. Dirty Pipe (CVE-2022-0847) is fixed in 20.04 HWE at ABI 35
# (USN-5317-1), and the bug was introduced in 5.8, so the window is
# 5.13.0-x for x <= 27. Booting anything else means scenario-19 silently stops
# being exploitable and its verify.sh would "pass" for the wrong reason -- the
# same failure mode meta4/kernel-vm guards against for S21/S22.
case "$RUNNING_KERNEL" in
    5.13.0-*-generic) ;;
    *) echo "ERROR: expected a 5.13.0-* kernel, got $RUNNING_KERNEL"; exit 1 ;;
esac
if [ -z "$ABI" ] || [ "$ABI" -gt 27 ] 2>/dev/null; then
    echo "ERROR: running ABI=$ABI; Dirty Pipe needs < 35 (fixed in 5.13.0-35.40)."
    grep '^\s*menuentry ' /boot/grub/grub.cfg 2>/dev/null | head -10 || true
    exit 1
fi

# -----------------------------------------------------------------------
# Hold the kernel
# -----------------------------------------------------------------------
apt-mark hold \
    "linux-image-${RUNNING_KERNEL}" \
    "linux-modules-${RUNNING_KERNEL}" \
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
# Docker Engine
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

usermod -aG docker vagrant || true

echo ""
echo "============================================"
echo " Kernel: $(uname -r)"
echo " Docker: $(docker --version)"
echo "============================================"
echo " CVE-2022-0847 (Dirty Pipe): VULNERABLE (ABI=$ABI <= 27)"
echo " scenario-19 is exercisable here in real exploit mode."
echo ""
