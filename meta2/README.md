# SysRepair-Bench: Metasploitable 2 Sub-Suite

**40 Docker scenarios** extracted from the OpenVAS scan of Metasploitable 2.0. Scenarios S34–S40 form the **Compensating Controls** band — cases where direct upgrade/remove would break a dependent legacy workload, so the agent must apply a network- or config-layer mitigation while keeping the service usable. See the [root README](../README.md) for benchmark overview, scenario format, and full Hardy-host setup (§3b).

## Scenario Breakdown

| Category | Scenarios | Count | Examples |
|---|---|---|---|
| **Configuration Errors** | S01-S15 | 15 | SSH weak ciphers, MySQL empty password, Apache TRACE, DistCC unrestricted |
| **Dependency/Patch Mgmt** | S16-S24 | 9 | vsftpd backdoor, UnrealIRCd backdoor, PHP-CGI RCE, Samba CVE-2007-2447 |
| **Access Control & Permissions** | S25-S29 | 5 | HTTP cleartext passwords, expired SSL certs, DRb no ACL |
| **Network Exposure** | S30-S33 | 4 | Telnet, rlogin, Ingreslock backdoor, Java RMI |
| **Compensating Controls** | S34-S40 | 7 | PHP-CGI mod_rewrite, TWiki/Tiki WAF, DRb ACL+bind-localhost, RMI+DistCC firewall scope, Samba hosts allow, EOL default-deny, VNC bind-localhost+SSH tunnel |

## Base image & host

`lpenz/ubuntu-hardy-amd64` (Ubuntu 8.04 Hardy Heron). Linux-host-only — quick sanity: `docker run --rm lpenz/ubuntu-hardy-amd64 /bin/true`; exit 139 means the host kernel lacks `vsyscall=emulate`.

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

## Excluded Vulnerabilities

The following OpenVAS findings were **excluded** as they require source-code fixes (SWE-bench territory):
- TWiki/TikiWiki XSS, SQL injection, CSRF, LFI vulnerabilities *(the legacy admin-exposure surface is now covered by S35 as a compensating-control scenario)*
- phpMyAdmin application code bugs
- awiki local file inclusion
- OS End of Life *(now covered by S39 as a compensating-control scenario)*

## Source

OpenVAS scan of Metasploitable 2.0 — PDF committed at [`../openvas-scan-reports/metasploitable-2.0.pdf`](../openvas-scan-reports/metasploitable-2.0.pdf).
