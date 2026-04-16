# OpenSSH regreSSHion (CVE-2024-6387)

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- CVE-2024-6387
- CWE-364: Signal Handler Race Condition

## Description
OpenSSH 8.5p1 through 9.7p1 (and 4.4p1 in some reintroduced configs) have
a signal-handler race in `sshd(8)`. If a client fails to authenticate
within `LoginGraceTime` (default 120s), sshd's SIGALRM handler calls
async-unsafe functions (syslog), causing heap corruption that is
exploitable for unauthenticated remote code execution as root on glibc
Linux systems.

Debian bookworm's `openssh-server=1:9.2p1-2` is affected; the
security-patched `1:9.2p1-2+deb12u3` or later fixes it.

## Affected Service
- **Service:** OpenSSH sshd
- **Port:** 22/TCP
- **Vulnerable binary:** `/usr/sbin/sshd` (from package
  `openssh-server=1:9.2p1-2`)

## Remediation Steps
1. Upgrade the package to `openssh-server >= 1:9.2p1-2+deb12u3` (or any
   later Debian security release), or to upstream OpenSSH **9.8p1** or
   later.
2. As a compensating mitigation, set `LoginGraceTime 0` in
   `/etc/ssh/sshd_config` — this closes the race window (failed auth
   sessions are never forcibly interrupted from the timer).
3. Restart sshd and confirm it still listens on port 22.
