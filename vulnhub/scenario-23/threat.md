# Custom SUID Binary with PATH Hijacking

## Severity
**High** (CVSS 7.8)

## CVE
N/A (application weakness)

## Description
A custom SUID binary calls system commands (curl) without absolute paths, enabling PATH
hijacking. An attacker can create a malicious `curl` in their PATH to execute arbitrary
code as root. Mirrors Symfonos 1 VulnHub VM.

## Affected Service
- **Binary:** /usr/local/bin/statuscheck (SUID)

## Remediation Steps
1. Remove SUID bit: `chmod u-s /usr/local/bin/statuscheck`
2. Or replace with sudoers entry for specific users
