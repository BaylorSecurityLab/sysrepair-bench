#!/bin/bash
# Stage 1b. Cloud-image-specific boot hardening; runs after install-old-kernel.sh
# and before the reboot.
#
# Kept separate from install-old-kernel.sh because that script is shared with the
# retired Vagrant flow, where the box shipped a known kernel and neither problem
# below could occur. On an Ubuntu cloud image both do.
#
# Problem 1 — initramfs. Cloud images can set MODULES=dep in
# /etc/initramfs-tools/initramfs.conf, which builds an initramfs containing only
# modules for hardware detected at build time. A newly built initramfs can then
# omit hv_storvsc, the root device is never found, and boot stops in the
# initramfs shell. From the Hyper-V host that is indistinguishable from a hang:
# heartbeat stays OK, no address ever appears. Force MODULES=most.
#
# Problem 2 — GRUB default. install-old-kernel.sh pins the kernel with
#   GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux <ver>"
# a human-readable submenu title that upstream can reword and that differs
# between the Vagrant box and the cloud image. A mismatch does not error; GRUB
# silently boots entry 0, i.e. the NEWEST kernel — the exact silent-wrong-kernel
# failure Assert-KernelAbi exists to catch. Rather than match a title, make the
# target the only kernel installed, so entry 0 is necessarily correct.
set -eux

export DEBIAN_FRONTEND=noninteractive
TARGET_KERNEL="5.15.0-25-generic"

if [ ! -f "/boot/vmlinuz-${TARGET_KERNEL}" ]; then
    echo "ERROR: /boot/vmlinuz-${TARGET_KERNEL} missing; stage 1 did not install it."
    exit 1
fi

# --- 1. initramfs with the Hyper-V drivers ---------------------------------
if grep -q '^MODULES=' /etc/initramfs-tools/initramfs.conf; then
    sed -i 's/^MODULES=.*/MODULES=most/' /etc/initramfs-tools/initramfs.conf
else
    echo 'MODULES=most' >> /etc/initramfs-tools/initramfs.conf
fi
update-initramfs -c -k "${TARGET_KERNEL}"

# --- 2. make the target the only kernel ------------------------------------
# Meta packages first: they would pull a newer kernel straight back in.
apt-get purge -y linux-image-virtual linux-headers-virtual linux-virtual \
                 linux-image-generic linux-headers-generic linux-generic \
                 2>/dev/null || true

# Then any other versioned kernel. Never the target, and never the package
# providing the currently running kernel if that is all we have left.
OTHERS=$(dpkg-query -W -f='${Package}\n' 'linux-image-*' 'linux-modules-*' 2>/dev/null \
         | grep -E '^linux-(image|modules)-[0-9]' \
         | grep -v "${TARGET_KERNEL}" || true)
for pkg in ${OTHERS}; do
    apt-get purge -y "${pkg}" || true
done

update-grub

echo "--- kernels remaining ---"
ls -1 /boot/vmlinuz-* || true
echo "--- grub default ---"
grep -E '^\s*(menuentry|GRUB_DEFAULT)' /boot/grub/grub.cfg 2>/dev/null | head -5 || true
