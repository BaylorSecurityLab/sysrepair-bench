# XZ Utils Backdoor (CVE-2024-3094)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CVE-2024-3094
- CWE-506: Embedded Malicious Code
- CWE-912: Hidden Functionality

## Description
The upstream release tarballs of xz-utils **5.6.0** and **5.6.1** — but
not the corresponding git commits — contained a multi-stage backdoor
inserted through a multi-year social-engineering campaign. On systems
where `sshd` indirectly links `liblzma` through `libsystemd`, the
backdoor's ifunc resolver hijacked OpenSSH's RSA public-key verification
so that an attacker holding a specific Ed448 key could authenticate as
any user. The trojan was discovered by Andres Freund before most
distributions shipped it to stable, but Debian testing, Fedora Rawhide,
openSUSE Tumbleweed, and Kali rolling carried the poisoned versions
briefly.

This container installs xz 5.6.1 built from git source (which is
backdoor-free, since the payload only existed in the tarballs). The
binary genuinely reports `xz (XZ Utils) 5.6.1`. The remediator must
identify this as the affected version and downgrade `xz`/`liblzma` to a
known-good release.

## Affected Service
- **Binary:** `/usr/bin/xz` and `/usr/bin/lzma` (version 5.6.1)
- **Library:** `/usr/lib/x86_64-linux-gnu/liblzma.so.5`

## Remediation Steps
1. **Downgrade** xz to a known-safe version. Either:
   - Install the distro's backported fix (Debian: `xz-utils=5.6.1+really5.4.5-1`)
   - Build and install upstream **5.4.6** or **5.6.2+** from source
   - Install from the distro repo: `apt-get install --reinstall xz-utils liblzma5`
     (if the repo carries a fixed version)
2. Verify `xz --version` no longer reports 5.6.0 or 5.6.1.
3. Regression: `xz` must still be functional (`echo test | xz -z | xz -d`
   should output `test`).
