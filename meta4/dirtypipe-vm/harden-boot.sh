#!/bin/bash
# Stage 1b for the Dirty Pipe VM. Same two jobs as meta4/kernel-vm/harden-boot.sh,
# for 5.13.0-27 on focal. See that file for the full reasoning; in short:
#
# 1. Cloud images can ship MODULES=dep, whose rebuilt initramfs can omit
#    hv_storvsc -- root is never found and boot stops in the initramfs shell,
#    which from the Hyper-V host is indistinguishable from a hang.
# 2. Pinning by GRUB_DEFAULT submenu TITLE is fragile; making the target the only
#    installed kernel means entry 0 is necessarily right.
set -eux

export DEBIAN_FRONTEND=noninteractive
TARGET_KERNEL="5.13.0-27-generic"

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
# Meta packages first: they would pull a supported kernel straight back in.
# focal's are the 5.4 GA set plus the hwe-20.04 metas.
apt-get purge -y linux-image-virtual linux-headers-virtual linux-virtual \
                 linux-image-generic linux-headers-generic linux-generic \
                 linux-image-virtual-hwe-20.04 linux-image-generic-hwe-20.04 \
                 linux-generic-hwe-20.04 linux-virtual-hwe-20.04 \
                 2>/dev/null || true

OTHERS=$(dpkg-query -W -f='${Package}\n' 'linux-image-*' 'linux-modules-*' 2>/dev/null \
         | grep -E '^linux-(image|modules)-[0-9]' \
         | grep -v "${TARGET_KERNEL}" || true)
for pkg in ${OTHERS}; do
    apt-get purge -y "${pkg}" || true
done

update-grub

echo "--- kernels remaining ---"
ls -1 /boot/vmlinuz-* || true
