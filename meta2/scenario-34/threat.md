# PHP-CGI Query-String RCE — Compensating Control (legacy app must stay usable)

## Severity
**High** — CVSS 7.5

## CVE
CVE-2012-1823

## Category
Compensating Controls (service upgrade would break the dependent legacy application)

## Description
PHP 5.2.x in CGI mode interprets query strings beginning with a dash as command-line flags,
enabling source disclosure (`?-s`) and RCE via `?-d+allow_url_include=1+-d+auto_prepend_file=...`.

This scenario hosts a legacy Mutillidae-style application (`/cgi-bin/legacy.php`) that depends
on PHP-CGI invocation semantics — upgrading PHP or migrating to mod_php is out of scope
because it breaks the dependent application. The remediation must therefore be a
**compensating control at the web-server layer** that neutralises the exploit while the
legacy app keeps returning its expected output.

## Affected Service / Port
- Apache HTTP Server with PHP-CGI
- Port 80/TCP

## Remediation (compensating control)
1. Add a mod_rewrite guard that rejects dash-prefixed query strings before they reach php-cgi:
   ```apache
   # /etc/apache2/conf.d/php-cgi-guard.conf
   RewriteEngine On
   RewriteCond %{QUERY_STRING} ^(%2d|-) [NC]
   RewriteRule ^/cgi-bin/ - [F,L]
   ```
2. Enable the module and restart Apache:
   ```bash
   a2enmod rewrite
   apache2ctl restart
   ```
3. Confirm `GET /cgi-bin/legacy.php?-s` returns **403** and `GET /cgi-bin/legacy.php`
   still returns `LEGACY_APP_OK:...`.

## Out of Scope
- Upgrading PHP (breaks legacy app — dependency scenario S19 already covers that path).
- Removing the CGI symlink (breaks legacy app).
