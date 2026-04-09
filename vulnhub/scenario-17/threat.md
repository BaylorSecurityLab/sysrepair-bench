# WordPress Admin Endpoints Exposed

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness)

## Description
WordPress admin endpoints (/wp-admin/, /wp-login.php) are accessible from all IP addresses,
enabling brute-force attacks against admin credentials. Mirrors the Mr-Robot VulnHub VM.

## Affected Service
- **Service:** Apache + WordPress
- **Port:** 80/TCP, 443/TCP
- **Configuration:** Apache virtual host files

## Remediation Steps
1. Add Apache ACLs to restrict /wp-admin and /wp-login.php to localhost
2. Use .htaccess or vhost config with `Require ip 127.0.0.1`
