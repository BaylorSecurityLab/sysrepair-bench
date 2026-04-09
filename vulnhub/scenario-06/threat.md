# PHP No open_basedir Restriction

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness)

## Description
PHP has no `open_basedir` restriction set, allowing PHP scripts to read and write files
anywhere on the filesystem. An attacker exploiting a file inclusion or file read vulnerability
can access /etc/passwd, /etc/shadow, configuration files, and other sensitive data.

Mirrors PwnOS 2.0 VulnHub VM and DC-9 scenarios.

## Affected Service
- **Service:** Apache + PHP
- **Port:** 80/TCP
- **Configuration:** /etc/php/7.3/apache2/php.ini

## Remediation Steps
1. Set `open_basedir = /var/www/html:/tmp` in php.ini
2. Restart Apache
