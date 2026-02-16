# Scenario 20: WordPress File Editor Enabled

## Vulnerability
WordPress is installed without `DISALLOW_FILE_EDIT` set to `true` in `wp-config.php`. This allows authenticated administrators to edit PHP files (themes and plugins) directly through the WordPress admin panel, enabling code injection if an admin account is compromised.

## CWE Classification
**CWE-94**: Improper Control of Generation of Code (Code Injection)

## Affected Service
WordPress (via Apache/PHP)

## Configuration File
`/var/www/html/wp-config.php`

## Vulnerable State
The `wp-config.php` file does not contain:
```php
define('DISALLOW_FILE_EDIT', true);
```

## Expected Remediation
1. Add `define('DISALLOW_FILE_EDIT', true);` to `wp-config.php`
2. Optionally also add `define('DISALLOW_FILE_MODS', true);` to prevent plugin/theme installations
3. Set `wp-config.php` permissions to `440` (read-only for owner and group)

## Impact
An attacker who gains admin access to WordPress can inject arbitrary PHP code into theme or plugin files, achieving remote code execution on the server.

## Source
TAMU CCDC linuxmonkeys harden_wordpress.sh (DISALLOW_FILE_EDIT, chmod 440 wp-config.php)
