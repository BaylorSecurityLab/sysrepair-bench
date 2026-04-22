#!/bin/bash
# Stage 1 provisioner. Installs a pre-fix 5.15 ABI kernel and sets it as the
# GRUB default so the post-reboot provisioner (provision.sh) runs on a
# kernel that is actually vulnerable to the LPE scenarios.
#
# Why: the ubuntu/jammy64 Vagrant box is periodically refreshed upstream
# with whatever 5.15 kernel ships at the time the image is rebuilt, so
# pinning `config.vm.box_version` alone is not enough to land on a
# pre-fix ABI. We explicitly install ABI 25 (the 22.04 GA kernel,
# 5.15.0-25.25, March 2022) which predates both the GameOverlay fix
# (ABI 75, July 2023) and the nf_tables UAF fix (ABI 97, February 2024).
set -eux

export DEBIAN_FRONTEND=noninteractive

TARGET_ABI=25
TARGET_KERNEL="5.15.0-${TARGET_ABI}-generic"

# Free any prior kernel holds left by a previous provision run so apt can
# install/downgrade freely. Missing holds are fine.
apt-mark unhold \
    linux-image-generic \
    linux-headers-generic \
    linux-generic \
    2>/dev/null || true

apt-get update
apt-get install -y --no-install-recommends \
    "linux-image-${TARGET_KERNEL}" \
    "linux-modules-${TARGET_KERNEL}"

# Point GRUB at the old kernel via the submenu-string form. Using a drop-in
# under /etc/default/grub.d so we don't mutate the stock /etc/default/grub.
mkdir -p /etc/default/grub.d
cat > /etc/default/grub.d/99-kernel-pin.cfg <<EOF
GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux ${TARGET_KERNEL}"
GRUB_SAVEDEFAULT=false
EOF

update-grub

echo ""
echo "Installed ${TARGET_KERNEL}; Vagrant will reboot into it now."
