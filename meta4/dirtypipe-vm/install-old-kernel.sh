#!/bin/bash
# Stage 1 for the Dirty Pipe VM. Installs Ubuntu 20.04 HWE kernel 5.13.0-27,
# which is vulnerable to CVE-2022-0847 (Dirty Pipe).
#
# WHY THIS VM EXISTS. Dirty Pipe affects 5.8 <= k < 5.15.25 / 5.13.0-28 /
# 5.10.102. meta4-kernel pins 5.15.0-25, which is 22.04 GA and ALREADY CARRIES
# the fix -- so scenario-19 can only be graded there in compensating-control mode
# (chattr +i on the SUID marker), never as a real exploit. 5.13.0-27 is the last
# 20.04 HWE ABI before USN-5317-1 landed the fix in -28, so the true kernel path
# is reachable here.
#
# WHY DIRECT .deb URLs. 5.13 HWE is EOL and superseded; `apt-get install
# linux-image-5.13.0-27-generic` on a current focal resolves to something newer
# or nothing at all. The debs are still published in the primary pool (verified
# HTTP 200 on archive.ubuntu.com and security.ubuntu.com -- NOT on
# old-releases), so fetch them explicitly. linux-image comes from
# linux-signed-hwe-5.13, linux-modules from linux-hwe-5.13.
set -eux

export DEBIAN_FRONTEND=noninteractive

ABI="5.13.0-27"
VER="5.13.0-27.29~20.04.1"
POOL="http://archive.ubuntu.com/ubuntu/pool/main/l"
WORK=/root/dp-kernel

apt-get update
apt-get install -y --no-install-recommends wget ca-certificates

mkdir -p "$WORK"
cd "$WORK"

# Order matters: modules before the signed image, which depends on them.
wget -q "${POOL}/linux-hwe-5.13/linux-modules-${ABI}-generic_${VER}_amd64.deb"
wget -q "${POOL}/linux-signed-hwe-5.13/linux-image-${ABI}-generic_${VER}_amd64.deb"

ls -la "$WORK"
dpkg -i "linux-modules-${ABI}-generic_${VER}_amd64.deb"
dpkg -i "linux-image-${ABI}-generic_${VER}_amd64.deb"
apt-get -f install -y

if [ ! -f "/boot/vmlinuz-${ABI}-generic" ]; then
    echo "ERROR: /boot/vmlinuz-${ABI}-generic missing after dpkg -i."
    exit 1
fi

echo "installed ${ABI}-generic; harden-boot.sh will make it the only kernel"
