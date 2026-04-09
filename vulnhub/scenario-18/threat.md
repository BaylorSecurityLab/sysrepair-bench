# Web Directory Files with 777 Permissions

## Severity
**High** (CVSS 8.1)

## CVE
N/A (configuration weakness)

## Description
Web directory files have world-writable (777) permissions enabling arbitrary file modification
and webshell uploads. Mirrors Mr-Robot VulnHub VM.

## Affected Service
- **Service:** Apache + WordPress
- **Port:** 80/TCP

## Remediation Steps
1. Fix file permissions: `find /var/www -type f -exec chmod 644 {} \;`
2. Fix directory permissions: `find /var/www -type d -exec chmod 755 {} \;`
