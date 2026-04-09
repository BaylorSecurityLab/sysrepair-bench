# VulnHub Benchmark Scenarios

Vulnerability benchmark scenarios derived from the **Comprehensive Analysis of VulnHub Virtual Machine Scoping for Automated Remediation Agents** report. Each scenario recreates a specific vulnerability from a VulnHub VM as a Docker container for automated remediation testing.

**Note:** Scenarios that duplicate vulnerabilities already covered in `ccdc/` or `meta2/` have been removed. All 30 scenarios below are unique to this folder.

## Scenario Index

| # | VulnHub VM | Vulnerability | Source | Base Image |
|---|-----------|---------------|--------|------------|
| 01 | Kioptrix Level 1 | Apache Deprecated SSL/TLS Protocols | CUSTOM | debian:11 |
| 02 | Kioptrix Level 1.1 | SQL Injection - No WAF/mod_security | CUSTOM | debian:11 |
| 03 | Kioptrix Level 1.3 | MySQL No secure_file_priv (OUTFILE) | CUSTOM | debian:11 |
| 04 | Metasploitable 1 | Tomcat Weak Default Credentials | CUSTOM | debian:11 |
| 05 | Metasploitable 2 | Samba Wide Links (CVE-2010-0926) | **PULLED** | tleemcjr/metasploitable2@sha256:e559... |
| 06 | PwnOS 2.0 | PHP No open_basedir Restriction | CUSTOM | debian:11 |
| 07 | DC-1 | Drupal 7 Drupalgeddon SQLi (CVE-2014-3704) | CUSTOM | debian:11 |
| 08 | DC-2 | WordPress Weak Admin Passwords | CUSTOM | debian:11 |
| 09 | DC-4 | PHP Command Injection (No Sanitization) | CUSTOM | debian:11 |
| 10 | DC-4 | Exim4 SUID Bit (CVE-2016-1531) | CUSTOM | debian:11 |
| 11 | DC-5 | Nginx Directory Traversal (LFI) | CUSTOM | debian:11 |
| 12 | DC-5 | GNU Screen SUID Bit (CVE-2017-5618) | CUSTOM | debian:11 |
| 13 | DC-7 | Drupal 8 Outdated Core | CUSTOM | debian:11 |
| 14 | DC-6 | WordPress Plugin Dirs Writable | CUSTOM | debian:11 |
| 15 | DC-8 | SMTP (Exim4) Exposed No Firewall | CUSTOM | debian:11 |
| 16 | DC-9 | knockd Insecure Configuration | CUSTOM | debian:11 |
| 17 | Mr-Robot | Admin Endpoints Exposed (wp-admin) | **PULLED** | supdevinci/mrrobot@sha256:9e9b... |
| 18 | Mr-Robot | Web Files 777 Permissions | CUSTOM | debian:11 |
| 19 | SickOs 1.1 | Squid Proxy Open ACLs | CUSTOM | debian:11 |
| 20 | SickOs 1.1 | CGI Shellshock (CVE-2014-6271) | CUSTOM | debian:11 |
| 21 | SickOs 1.2 | Root Cron Executes from /tmp | CUSTOM | debian:11 |
| 22 | FristiLeaks 1.3 | PHP Execution in Uploads Directory | CUSTOM | debian:11 |
| 23 | Symfonos 1 | SUID Binary PATH Hijacking | CUSTOM | debian:11 |
| 24 | Symfonos 2 | MySQL User with FILE/SUPER Privileges | CUSTOM | debian:11 |
| 25 | Symfonos 3 | CGI-bin Lax Permissions | CUSTOM | debian:11 |
| 26 | Symfonos 4 | World-Readable Auth/Access Logs | CUSTOM | debian:11 |
| 27 | LinSecurity | Dangerous Sudoers Wildcard Entries | CUSTOM | debian:11 |
| 28 | Brainpan 2 | Execute Permissions on Staging Dirs | CUSTOM | debian:11 |
| 29 | De-ICE S1.120 | Custom Service on All Interfaces | CUSTOM | debian:11 |
| 30 | De-ICE S1.130 | Binaries with Dangerous Capabilities | CUSTOM | debian:11 |

## Summary

| Type | Count | Details |
|------|-------|---------|
| **PULLED** | 2 | Scenarios 05 (Metasploitable 2), 17 (Mr-Robot) |
| **CUSTOM** | 28 | All others - built from debian:11 base |
| **Total** | 30 | |

### Pulled Docker Images (pinned to SHA digest)

| Image | Source VM | Scenarios |
|-------|----------|-----------|
| `tleemcjr/metasploitable2@sha256:e559450b...` | Metasploitable 2 | 05 |
| `supdevinci/mrrobot@sha256:9e9b6cb8f7...` | Mr-Robot | 17 |

## Removed Scenarios (overlaps with ccdc/ or meta2/)

20 scenarios were removed to avoid duplication with existing benchmarks. See git history for details.

## Usage

Each scenario contains:
- `Dockerfile` - Builds the vulnerable container
- `threat.md` - Documents the vulnerability, affected service, and remediation steps
- `verify.sh` - Verification script (exit 0 = remediated, exit 1 = still vulnerable)

```bash
# Build and run a scenario
cd scenario-XX
docker build -t vulnhub-XX .
docker run -d --name vulnhub-XX vulnhub-XX

# Verify remediation
docker exec vulnhub-XX /bin/bash /verify.sh
```
