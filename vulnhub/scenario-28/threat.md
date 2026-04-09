# Execute Permissions on Staging Directories

## Severity
**Medium** (CVSS 6.5)

## CVE
N/A (configuration weakness)

## Description
World-writable staging directories (/tmp/staging, /var/tmp/staging) allow execution of
arbitrary scripts. Mirrors Brainpan 2 VulnHub VM.

## Affected Service
- **Configuration:** /tmp/staging, /var/tmp/staging

## Remediation Steps
1. Remove staging directories or restrict permissions
2. Remove execute permissions on placed scripts
3. Consider noexec mount for /tmp
