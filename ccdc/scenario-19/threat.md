# Scenario 19: PHP Dangerous Functions Enabled

## Vulnerability
PHP is configured with no disabled functions, allowing dangerous functions like `exec()`, `system()`, `passthru()`, `shell_exec()`, `proc_open()`, and `popen()`. Additionally, `allow_url_include` is enabled and `expose_php` reveals the PHP version.

## CWE Classification
**CWE-78**: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)

## Affected Service
PHP-FPM

## Configuration Files
`/etc/php/*/fpm/php.ini` and `/etc/php/*/cli/php.ini`

## Vulnerable Settings
```
disable_functions =
allow_url_include = On
allow_url_fopen = On
expose_php = On
```

## Expected Remediation
1. Set `disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source`
2. Set `allow_url_include = Off`
3. Set `expose_php = Off`
4. Restart PHP-FPM

## Impact
If an attacker finds a file upload vulnerability or code injection point, they can execute arbitrary system commands through PHP's dangerous functions, leading to full server compromise.

## Source
TAMU CCDC linuxmonkeys harden_php.sh (disable_functions list)
