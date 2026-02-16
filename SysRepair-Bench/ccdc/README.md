# SysRepair-Bench

A benchmark of **50 reproducible scenarios** for evaluating autonomous system remediation agents.
Each scenario is a Docker container based on **Ubuntu 25.10 (Quantal)** with:

1. **Vulnerable State** - A `Dockerfile` that sets up the misconfigured/vulnerable environment
2. **Threat Context** - A `threat.md` describing the vulnerability and associated CWE
3. **Success Oracle** - A `verify.sh` that tests exploitation (PoC) and system functionality (regression)

Remediation is successful **only if** the PoC fails AND the functionality test passes.

## Categories

| Category | Scenarios | Description |
|----------|-----------|-------------|
| **Configuration Vulnerabilities** | 01-25 | Fixable by editing config files (sshd_config, nginx.conf, my.cnf, etc.) |
| **Dependency Management** | 26-38 | Fixable by installing, upgrading, or removing packages |
| **Permissions/Access** | 39-50 | Fixable by chmod, chown, usermod, or ACL changes |

## Source Material

Scenarios derived from CCDC (Collegiate Cyber Defense Competition) team hardening scripts:
- TAMU linuxmonkeys toolkit (2021)
- LATech 2023 SWCCDC Regionals scripts
- UTSA 2023 SWCCDC scripts
- Team internal checklists (2018-2024)

## Usage

```bash
# Build a single scenario
cd scenario-01
docker build -t sysrepair-01 .

# Run the container
docker run -d --name test-01 sysrepair-01

# Agent performs remediation inside the container...

# Verify remediation
docker exec test-01 /opt/verify.sh
# Exit code 0 = remediation successful
# Exit code 1 = remediation failed
```

## Scenario Index

### Configuration Vulnerabilities (01-25)
| # | Scenario | CWE | Service |
|---|----------|-----|---------|
| 01 | SSH permits root login | CWE-250 | sshd |
| 02 | SSH allows empty passwords | CWE-258 | sshd |
| 03 | SSH weak ciphers & protocol | CWE-327 | sshd |
| 04 | SSH X11 forwarding + no MaxAuthTries | CWE-307 | sshd |
| 05 | SSH password auth with no key restriction | CWE-308 | sshd |
| 06 | Apache ServerTokens Full / ServerSignature On | CWE-200 | apache2 |
| 07 | Apache directory listing enabled | CWE-548 | apache2 |
| 08 | Apache TRACE method enabled | CWE-693 | apache2 |
| 09 | Nginx server_tokens on / version disclosure | CWE-200 | nginx |
| 10 | Nginx autoindex on (directory listing) | CWE-548 | nginx |
| 11 | MySQL remote root login + no bind-address | CWE-284 | mysql |
| 12 | MySQL local-infile enabled | CWE-284 | mysql |
| 13 | PostgreSQL pg_hba.conf trust all connections | CWE-284 | postgresql |
| 14 | PostgreSQL listen_addresses = '*' unprotected | CWE-668 | postgresql |
| 15 | vsftpd anonymous upload enabled | CWE-434 | vsftpd |
| 16 | vsftpd no SSL/TLS enforcement | CWE-319 | vsftpd |
| 17 | BIND DNS zone transfer unrestricted | CWE-200 | bind9 |
| 18 | Samba anonymous share access | CWE-284 | samba |
| 19 | PHP dangerous functions enabled | CWE-78 | php-fpm |
| 20 | WordPress file editor enabled | CWE-94 | wordpress |
| 21 | Kernel IP forwarding enabled | CWE-1188 | sysctl |
| 22 | Kernel ASLR disabled | CWE-330 | sysctl |
| 23 | SYN cookies disabled / source routing on | CWE-400 | sysctl |
| 24 | ICMP redirects accepted / martians not logged | CWE-940 | sysctl |
| 25 | Redis bound to 0.0.0.0 no auth | CWE-284 | redis |

### Dependency Management (26-38)
| # | Scenario | CWE | Issue |
|---|----------|-----|-------|
| 26 | Hacking tools installed (nmap, netcat, hydra) | CWE-1104 | Unauthorized packages |
| 27 | Telnet server running (no SSH alternative) | CWE-319 | Insecure protocol |
| 28 | rsh/rlogin services enabled | CWE-319 | Insecure remote shell |
| 29 | No firewall installed (ufw absent) | CWE-1188 | Missing security control |
| 30 | fail2ban not installed (SSH brute-force open) | CWE-307 | Missing rate limiting |
| 31 | No auditd installed | CWE-778 | Missing audit logging |
| 32 | AppArmor not enforcing | CWE-693 | Missing MAC |
| 33 | Outdated OpenSSL with known CVE | CWE-327 | Vulnerable dependency |
| 34 | unattended-upgrades not configured | CWE-1104 | No auto-patching |
| 35 | NFS server unnecessarily exposed | CWE-284 | Unnecessary service |
| 36 | CUPS running on server (unnecessary) | CWE-1188 | Unnecessary service |
| 37 | Avahi/mDNS daemon running | CWE-1188 | Unnecessary service |
| 38 | Compiler tools (gcc/make) on production | CWE-1104 | Unnecessary dev tools |

### Permissions/Access (39-50)
| # | Scenario | CWE | Issue |
|---|----------|-----|-------|
| 39 | /etc/shadow world-readable | CWE-732 | File permission |
| 40 | /etc/passwd writable by others | CWE-732 | File permission |
| 41 | SUID bit on python/perl/bash | CWE-269 | Privilege escalation |
| 42 | World-writable /tmp without sticky bit | CWE-732 | Missing sticky bit |
| 43 | Unauthorized UID 0 user | CWE-269 | Rogue admin |
| 44 | Unauthorized user in sudo group | CWE-269 | Excess privileges |
| 45 | Root account unlocked with weak password | CWE-521 | Weak credentials |
| 46 | No password aging policy | CWE-263 | Password lifecycle |
| 47 | No PAM password complexity (pwquality) | CWE-521 | Weak policy |
| 48 | Crontab with reverse shell backdoor | CWE-506 | Backdoor |
| 49 | Rogue SSH authorized_keys on root | CWE-506 | Backdoor |
| 50 | World-writable web document root | CWE-732 | File permission |
