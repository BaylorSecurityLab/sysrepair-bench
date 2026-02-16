# SysRepair-Bench: Metasploitable 2 Extension

## Overview

This directory contains **33 Docker scenarios** extracted from the OpenVAS vulnerability scan of Metasploitable 2.0. Each scenario is designed to reproduce a specific vulnerability that can be remediated through **system administration actions** (configuration changes, package updates, permission fixes, or service management).

## Project Structure

```
meta2/
├── metasploitable2-docker-scenarios.md    # Detailed scenario documentation
├── metasploitable-2.0-openvas.pdf         # Source OpenVAS scan report
├── README.md                               # This file
└── scenario-{01..33}/                      # Individual scenarios
    ├── Dockerfile                          # Vulnerable container setup
    ├── threat.md                           # Threat description & remediation
    └── verify.sh                           # Verification script (PoC + regression)
```

## Scenario Breakdown

| Category | Scenarios | Count | Examples |
|---|---|---|---|
| **Configuration Errors** | S01-S15 | 15 | SSH weak ciphers, MySQL empty password, Apache TRACE, DistCC unrestricted |
| **Dependency/Patch Mgmt** | S16-S24 | 9 | vsftpd backdoor, UnrealIRCd backdoor, PHP-CGI RCE, Samba CVE-2007-2447 |
| **Access Control & Permissions** | S25-S29 | 5 | HTTP cleartext passwords, expired SSL certs, DRb no ACL |
| **Network Exposure** | S30-S33 | 4 | Telnet, rlogin, Ingreslock backdoor, Java RMI |

## Base Image

All scenarios use **`navig/ubuntu:8.04`** to match Metasploitable 2's Ubuntu 8.04 (Hardy Heron) base.

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

## Excluded Vulnerabilities

The following OpenVAS findings were **excluded** as they require source code fixes (SWE-bench territory):
- TWiki/TikiWiki XSS, SQL injection, CSRF, LFI vulnerabilities
- phpMyAdmin application code bugs
- awiki local file inclusion
- OS End of Life (inherent to Ubuntu 8.04)

## Integration with SysRepair-Bench

These scenarios extend the core 50-scenario benchmark (scenario-01 through scenario-50) with **real-world Metasploitable 2 vulnerabilities**. They can be:

1. **Evaluated independently** as a Metasploitable 2 remediation benchmark
2. **Merged into SysRepair-Bench** as scenarios 51-83
3. **Used for OpenVAS integration testing** (verify OpenVAS detects these vulns)

## Credits

- **Source:** OpenVAS scan of Metasploitable 2.0 (Feb 13, 2019)
- **Target Platform:** NDSS 2027 Submission
- **Research:** Neurosymbolic Planning for Verifiable Autonomous System Remediation

## License

Part of the SysRepair-Bench project for NDSS 2027.
