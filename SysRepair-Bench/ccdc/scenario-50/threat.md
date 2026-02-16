# Scenario 50: World-Writable Web Document Root

## Vulnerability
The web document root `/var/www/html` has permissions `777` (world-readable, writable, and executable). Any user on the system can modify, create, or delete web content, including injecting malicious scripts or web shells.

## CWE Classification
**CWE-732**: Incorrect Permission Assignment for Critical Resource

## Affected Service
Nginx (web server document root)

## Directory
`/var/www/html`

## Vulnerable State
```
drwxrwxrwx /var/www/html  (777 - world-writable)
```

## Expected Remediation
Set proper ownership and permissions:
```bash
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html
find /var/www/html -type f -exec chmod 644 {} \;
```

## Impact
Any local user or compromised service can modify web content, inject JavaScript for XSS/phishing, place web shells for remote access, or deface the website.

## Source
General web server hardening best practices, team internal checklists
