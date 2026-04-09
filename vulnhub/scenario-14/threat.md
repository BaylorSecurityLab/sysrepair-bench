# WordPress Plugin Directories World-Writable

## Severity
**High** (CVSS 8.1)

## CVE
N/A (configuration weakness)

## Description
WordPress plugin directories have world-writable (777) permissions, allowing any user
to install, modify, or replace plugins. Vulnerable plugins remain active. Mirrors DC-6 VulnHub VM.

## Affected Service
- **Service:** Apache + WordPress
- **Port:** 80/TCP
- **Configuration:** /var/www/html/wp-content/plugins/

## Remediation Steps
1. Fix permissions: `chmod -R 755 /var/www/html/wp-content/plugins`
2. Set ownership: `chown -R www-data:www-data /var/www/html/wp-content`
3. Disable vulnerable plugins
