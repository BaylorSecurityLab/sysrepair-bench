# SysRepair-Bench: Metasploitable 2 Extension

## Overview

This directory contains **40 Docker scenarios** extracted from the OpenVAS vulnerability scan of Metasploitable 2.0. Each scenario is designed to reproduce a specific vulnerability that can be remediated through **system administration actions** (configuration changes, package updates, permission fixes, or service management). Scenarios **S34–S40** form the **Compensating Controls** category: cases where direct remediation (upgrade/remove) would break a dependent legacy workload, so the agent must apply a network- or config-layer mitigation while keeping the service usable.

## Project Structure

```
meta2/
├── metasploitable2-docker-scenarios.md    # Detailed scenario documentation
├── README.md                               # This file
└── scenario-{01..40}/                      # Individual scenarios (S34-S40 = Compensating Controls)
    ├── Dockerfile                          # Vulnerable container setup
    ├── threat.md                           # Threat description & remediation
    └── verify.sh                           # Verification script (PoC + regression)
```

The source OpenVAS PDF lives in the repo-level
[`openvas-scan-reports/metasploitable-2.0-openvas.pdf`](../openvas-scan-reports/metasploitable-2.0.pdf).

## Scenario Breakdown

| Category | Scenarios | Count | Examples |
|---|---|---|---|
| **Configuration Errors** | S01-S15 | 15 | SSH weak ciphers, MySQL empty password, Apache TRACE, DistCC unrestricted |
| **Dependency/Patch Mgmt** | S16-S24 | 9 | vsftpd backdoor, UnrealIRCd backdoor, PHP-CGI RCE, Samba CVE-2007-2447 |
| **Access Control & Permissions** | S25-S29 | 5 | HTTP cleartext passwords, expired SSL certs, DRb no ACL |
| **Network Exposure** | S30-S33 | 4 | Telnet, rlogin, Ingreslock backdoor, Java RMI |
| **Compensating Controls** | S34-S40 | 7 | PHP-CGI mod_rewrite, TWiki/Tiki WAF, DRb ACL+bind-localhost, RMI+DistCC firewall scope, Samba hosts allow, EOL default-deny, VNC bind-localhost+SSH tunnel |

## Base Image

All scenarios use **`lpenz/ubuntu-hardy-amd64`** (Ubuntu 8.04 Hardy Heron) to match Metasploitable 2's base OS.

## Host Requirements (IMPORTANT)

Ubuntu 8.04's glibc uses the legacy `vsyscall` page, which was **removed** from the
upstream Linux kernel in 5.18 and is disabled by default in:

- Docker Desktop for Windows / macOS (uses a WSL2 or LinuxKit kernel ≥ 6.x without `vsyscall=emulate`).
- Most modern Linux distro kernels ≥ 6.x unless the `vsyscall=emulate` boot parameter is set.

On those hosts **every Hardy container exits with SIGSEGV (exit 139)** before `apt-get`
even runs. This affects **all 40 meta2 scenarios**, not just the new ones.

**Supported test hosts:**

1. A native Linux host booted with `vsyscall=emulate` on the kernel command line. Verify with:
   ```bash
   cat /proc/cmdline | grep -o 'vsyscall=[a-z]*'
   ```
2. A WSL2 custom kernel rebuilt with `CONFIG_LEGACY_VSYSCALL_EMULATE=y` (non-trivial).

If `docker run --rm lpenz/ubuntu-hardy-amd64 /bin/true` exits 0, the host is fine.
If it exits 139, switch to one of the supported hosts above before continuing.

### Additional capabilities

Scenarios `scenario-37` (DistCC + Java RMI firewall scoping) and `scenario-39`
(Ubuntu 8.04 EOL default-deny) manipulate `iptables` in the container and therefore
require `--cap-add=NET_ADMIN`:

```bash
docker run -d --cap-add=NET_ADMIN --name meta2-s37 meta2-s37
```

## Scenario Format

Each scenario follows the SysRepair-Bench standard:

1. **Dockerfile**: Sets up the vulnerable service/configuration
2. **threat.md**: Documents:
   - Severity, CVSS score, CVE references
   - Vulnerable configuration
   - Impact
   - Step-by-step remediation instructions
3. **verify.sh**: Dual-check verification:
   - **PoC check**: Vulnerability should NOT be exploitable (exit 1 if still vulnerable)
   - **Regression check**: Service should still function correctly (exit 1 if broken)

## Quick Start

### Build a scenario:
```bash
cd scenario-01
docker build -t meta2-s01-ssh-weak-ciphers .
```

> **Host check:** first confirm the Hardy base works on your host —
> `docker run --rm lpenz/ubuntu-hardy-amd64 /bin/true`. If it exits 139, see
> "Host Requirements" above.

### Run the vulnerable container:
```bash
docker run -d -p 2222:22 --name meta2-s01 meta2-s01-ssh-weak-ciphers
```

### Scan with OpenVAS:
```bash
# OpenVAS should detect the vulnerability
# Example: SSH Weak Encryption Algorithms Supported
```

### Remediate (enter container):
```bash
docker exec -it meta2-s01 /bin/bash

# Follow remediation steps from threat.md
# Example for S01:
sed -i 's/^#Ciphers.*/Ciphers aes256-ctr,aes192-ctr,aes128-ctr/' /etc/ssh/sshd_config
service ssh restart
exit
```

### Verify remediation:
```bash
docker exec meta2-s01 /bin/bash verify.sh
# Should output: === PASS: Vulnerability remediated, service operational ===
```

## Scenario Index

| ID | Vulnerability | Port | CVSS | CVE |
|---|---|---|---|---|
| S01 | SSH Weak Encryption Algorithms | 22 | 4.3 | - |
| S02 | SSH Weak MAC Algorithms | 22 | 2.6 | - |
| S03 | SSH Default Credentials | 22 | 7.5 | - |
| S04 | FTP Anonymous Login | 21 | 6.4 | CVE-1999-0497 |
| S05 | FTP Unencrypted Login | 21 | 4.8 | - |
| S06 | MySQL Root Empty Password | 3306 | 9.0 | - |
| S07 | PostgreSQL Weak Password | 5432 | 9.0 | - |
| S08 | VNC Weak Password | 5900 | 9.0 | - |
| S09 | VNC Unencrypted Data Transmission | 5900 | 4.8 | - |
| S10 | Apache TRACE/TRACK Enabled | 80 | 5.8 | CVE-2003-1567 |
| S11 | Apache PUT/DELETE (WebDAV) | 80 | 7.5 | - |
| S12 | Apache /doc Browsable | 80 | 5.0 | CVE-1999-0678 |
| S13 | phpinfo() Exposed | 80 | 7.5 | - |
| S14 | Postfix SMTP VRFY/EXPN | 25 | 5.0 | - |
| S15 | DistCC Unrestricted RCE | 3632 | 9.3 | CVE-2004-2687 |
| S16 | vsftpd 2.3.4 Backdoor | 21/6200 | 7.5 | - |
| S17 | UnrealIRCd Backdoor | 6667 | 7.5 | CVE-2010-2075 |
| S18 | UnrealIRCd Auth Spoofing | 6667 | 6.8 | CVE-2016-7144 |
| S19 | PHP-CGI Query String RCE | 80 | 7.5 | CVE-2012-1823 |
| S20 | Samba MS-RPC RCE | 445 | 6.0 | CVE-2007-2447 |
| S21 | OpenSSL CCS Injection | 5432 | 6.8 | CVE-2014-0224 |
| S22 | Postfix STARTTLS Injection | 25 | 6.8 | CVE-2011-0411 |
| S23 | PostgreSQL SSLv3 POODLE | 5432 | 4.3 | CVE-2014-3566 |
| S24 | FREAK/LogJam Export Ciphers | 25 | 4.3 | CVE-2015-0204/4000 |
| S25 | HTTP Cleartext Passwords | 80 | 4.8 | - |
| S26 | Apache httpOnly Cookie Leak | 80 | 4.3 | - |
| S27 | SSL/TLS Certificate Expired | 25/5432 | 5.0 | - |
| S28 | SSL/TLS Weak Signature | 25/5432 | 4.0 | - |
| S29 | DRb Unrestricted RCE | 8787 | 10.0 | - |
| S30 | Telnet Cleartext Service | 23 | 4.8 | - |
| S31 | rlogin Passwordless | 513 | 7.5 | CVE-1999-0651 |
| S32 | Ingreslock Backdoor | 1524 | 10.0 | - |
| S33 | Java RMI Insecure Config | 1099 | 10.0 | - |
| S34 | PHP-CGI RCE — mod_rewrite compensating (legacy app stays usable) | 80 | 7.5 | CVE-2012-1823 |
| S35 | TWiki/Tiki legacy admin exposure — WAF/LocationMatch compensating | 80 | 7.5 | CVE-2008-5304 / multi |
| S36 | DRb unrestricted RCE — drb/acl.rb + bind-localhost compensating | 8787 | 10.0 | - |
| S37 | Java RMI + DistCC open-to-world — iptables + --allow compensating | 1099/3632 | 10.0/9.3 | CVE-2011-3556 / CVE-2004-2687 |
| S38 | Samba `username map script` RCE — directive removal + hosts allow compensating | 445 | 6.0 | CVE-2007-2447 |
| S39 | Ubuntu 8.04 EOL — default-deny host-firewall compensating | host | high | multi |
| S40 | VNC exposed on 0.0.0.0 — bind-localhost + SSH-tunnel compensating | 5900 | 9.0 | - |

## Scope Alignment

These scenarios target the **System Administration layer** per the NDSS 2027 research plan:

| PDDL Action | Remediation Type | Examples |
|---|---|---|
| `edit_file_parameter` | Config file edits | sshd_config, vsftpd.conf, smb.conf, httpd.conf |
| `update_package` | Package upgrades | Upgrade PHP, Samba, Postfix, OpenSSL |
| `remove_package` | Service removal | Remove telnetd, rsh-server, backdoors |
| `chmod` / `chown` | Permission fixes | File permissions, certificate ownership |
| `service_stop` | Service management | Disable rlogin, telnet, ingreslock |
| `iptables_block` | Firewall rules | Block backdoor ports (1524, 1099) |
| `iptables_scope` | Source-IP / interface scoping (**compensating**) | Allow trusted subnet only for 1099/3632 (S37), default-deny INPUT + SSH accept (S39) |
| `waf_rule` / `mod_rewrite_guard` | Web-server layer request filtering (**compensating**) | Block `?-` query-string to php-cgi (S34), lock down TWiki admin paths (S35) |
| `bind_localhost` | Restrict listener to loopback (**compensating**) | dRuby (S36), VNC (S40) — reachable only via SSH tunnel or trusted-side ACL |
| `directive_remove` | Delete an unsafe config directive (**compensating**) | Drop `username map script` from `smb.conf` (S38) |

## Excluded Vulnerabilities

The following OpenVAS findings were **excluded** as they require source code fixes (SWE-bench territory):
- TWiki/TikiWiki XSS, SQL injection, CSRF, LFI vulnerabilities *(the legacy admin-exposure surface is now covered by S35 as a compensating-control scenario)*
- phpMyAdmin application code bugs
- awiki local file inclusion
- OS End of Life *(now covered by S39 as a compensating-control scenario)*

## Integration with SysRepair-Bench

These scenarios extend the core 50-scenario benchmark (scenario-01 through scenario-50) with **real-world Metasploitable 2 vulnerabilities**. They can be:

1. **Evaluated independently** as a Metasploitable 2 remediation benchmark
2. **Merged into SysRepair-Bench** as scenarios 51-90 (50 core + 40 meta2)
3. **Used for OpenVAS integration testing** (verify OpenVAS detects these vulns)

## Credits

- **Source:** OpenVAS scan of Metasploitable 2.0 (Feb 13, 2019)
- **Target Platform:** NDSS 2027 Submission
- **Research:** Neurosymbolic Planning for Verifiable Autonomous System Remediation

## License

Part of the SysRepair-Bench project for NDSS 2027.
