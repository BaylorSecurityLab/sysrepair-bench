# GameOver(lay) — Ubuntu OverlayFS LPE (CVE-2023-2640 / CVE-2023-32629)

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CVE-2023-2640, CVE-2023-32629
- CWE-863: Incorrect Authorization

## Description
Ubuntu's downstream patches to OverlayFS (commits that predate kernel
5.19) skipped permission and capability checks when the kernel performed
a copy-up of a file carrying extended attributes (file capabilities).
An unprivileged user can set `cap_setuid=ep` on a file in a tmpfs-backed
lower layer, trigger a copy-up into an overlay upper layer in their own
namespace, and then execute the resulting binary with elevated
capabilities.

## Affected Service
- **Ubuntu kernels**: only the three lines that shipped the flawed SAUCE
  patch — 22.04 GA `5.15`, 22.04 HWE `5.19`, and 23.04 `6.2`. The
  security tracker marks 16.04, 18.04, 20.04, 23.10 and 24.04 "Not
  affected".
- Non-Ubuntu distributions are not affected (their OverlayFS does not
  carry the downstream patches that introduced this bug)

## Remediation Steps
1. Upgrade the host kernel to a patched Ubuntu release:
   `apt-get update && apt-get install -y linux-image-generic` and
   reboot. Fixed kernels: 5.15.0-177-generic / 5.19.0-50-generic /
   6.2.0-26-generic or later.
2. Compensating control: disable user namespaces
   (`kernel.unprivileged_userns_clone=0` in sysctl), which prevents the
   unprivileged OverlayFS mount required by the exploit.
3. Verify `/opt/marker-bash` still executes.
