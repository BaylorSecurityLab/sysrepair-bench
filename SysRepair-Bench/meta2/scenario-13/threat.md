# phpinfo() Exposed

## Severity
**High** | CVSS 7.5

## CVE
N/A (misconfiguration / information disclosure)

## Description
A PHP file containing a call to `phpinfo()` is publicly accessible in the web server document root. The `phpinfo()` function outputs an extensive amount of information about the PHP environment, including:

- PHP version and configuration directives
- Loaded extensions and their versions
- Server environment variables (potentially including sensitive paths)
- HTTP request headers and cookie values
- Operating system version and architecture
- Database connection details if configured via PHP
- Compilation options and enabled modules

This information is invaluable to an attacker performing reconnaissance, as it reveals the exact software stack, enabled features, file paths, and potential attack vectors. Combined with known vulnerabilities for the disclosed versions, an attacker can craft targeted exploits against the system.

## Affected Service
- **Service:** Apache HTTP Server 2.2 with PHP5
- **Port:** 80/tcp
- **Protocol:** HTTP
- **File:** `/var/www/phpinfo.php`

## Vulnerable Configuration
The file `/var/www/phpinfo.php` exists in the web root and contains:

```php
<?php phpinfo(); ?>
```

Accessing `http://target/phpinfo.php` displays the full PHP configuration to any remote user.

## Remediation Steps
1. **Remove the phpinfo file** (recommended):
   ```bash
   rm /var/www/phpinfo.php
   ```
2. If phpinfo is needed for debugging, restrict access:
   ```apache
   <Files "phpinfo.php">
       Order deny,allow
       Deny from all
       Allow from 127.0.0.1
   </Files>
   ```
3. Alternatively, use `php -i` on the command line for local diagnostics instead of exposing it via the web.
4. Audit the web root for any other debug/diagnostic files:
   ```bash
   find /var/www -name "*.php" -exec grep -l "phpinfo" {} \;
   ```
