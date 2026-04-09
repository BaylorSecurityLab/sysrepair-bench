# Nginx Directory Traversal Not Blocked

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness)

## Description
Nginx is configured without location rules to block directory traversal sequences and
dotfile access. An attacker can use path traversal (`../`) to access files outside the
web root, including sensitive configuration files and system data.

Mirrors the DC-5 VulnHub VM with Nginx LFI vulnerabilities.

## Affected Service
- **Service:** Nginx + PHP-FPM
- **Port:** 80/TCP
- **Configuration:** /etc/nginx/sites-available/default

## Remediation Steps
1. Add to nginx config: `location ~ /\. { deny all; }`
2. Add: `location ~ \.\. { deny all; }`
3. Restart nginx: `service nginx restart`
