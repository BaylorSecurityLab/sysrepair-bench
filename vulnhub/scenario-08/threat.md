# WordPress Weak Admin Passwords

## Severity
**Critical** (CVSS 9.8)

## CVE
N/A (configuration weakness)

## Description
WordPress admin accounts use weak passwords with outdated phpass portable hashing ($P$
prefix). These hashes are vulnerable to offline brute-force attacks. The admin password
is easily crackable using dictionary attacks.

Mirrors the DC-2 VulnHub VM with weak WordPress credentials.

## Affected Service
- **Service:** WordPress / MariaDB
- **Port:** 80/TCP, 3306/TCP
- **Configuration:** wordpress.wp_users database table

## Remediation Steps
1. Reset admin passwords using bcrypt/Argon2id hashing
2. Use WP-CLI or direct DB update to set strong password hashes ($2y$ prefix)
3. Enforce password policy
