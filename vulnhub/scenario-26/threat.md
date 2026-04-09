# World-Readable System and Access Logs

## Severity
**Medium** (CVSS 5.3)

## CVE
N/A (configuration weakness)

## Description
System logs (/var/log/auth.log, /var/log/apache2/access.log) have world-readable and
world-writable (666) permissions. A web user can inject PHP payloads into logs for
log poisoning attacks. Mirrors Symfonos 4 VulnHub VM.

## Affected Service
- **Service:** rsyslog, Apache
- **Configuration:** /var/log/ file permissions

## Remediation Steps
1. `chown root:adm /var/log/auth.log /var/log/apache2/access.log`
2. `chmod 640 /var/log/auth.log /var/log/apache2/access.log`
