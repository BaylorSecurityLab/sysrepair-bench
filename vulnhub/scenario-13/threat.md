# Drupal 8 Outdated Core

## Severity
**Critical** (CVSS 9.8)

## CVE
Multiple (SA-CORE-2018-002, SA-CORE-2018-004)

## Description
Drupal 8 core is at version 8.5.0 which contains multiple critical security vulnerabilities
including remote code execution. The system requires security patches applied via Drush
or manual core update.

Mirrors the DC-7 VulnHub VM.

## Affected Service
- **Service:** Apache + Drupal 8
- **Port:** 80/TCP
- **Configuration:** /var/www/html/core/lib/Drupal.php

## Remediation Steps
1. Update VERSION to 8.6.x or higher in Drupal.php and VERSION.txt
2. Clear caches via Drush if available
3. Restart Apache
