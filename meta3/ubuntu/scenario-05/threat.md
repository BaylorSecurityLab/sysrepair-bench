# Unprotected Web Application Installer Pages

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-16: Configuration
- CWE-284: Improper Access Control
- OpenVAS: "Unprotected Web App / Device Installers (HTTP)"

## Description
The Drupal and phpMyAdmin installer endpoints remain reachable over HTTP after
installation is complete. An unauthenticated attacker who discovers these pages
can reinitialize the application database, overwrite site settings, or configure
a new phpMyAdmin installation pointing at arbitrary MySQL credentials.

Affected endpoints:
- `/drupal/install.php` — Drupal setup wizard; allows full database reinitialisation
- `/phpmyadmin/setup/index.php` — phpMyAdmin configuration generator; can write a
  new `config.inc.php` that grants the attacker MySQL root-equivalent access to the
  management interface

## Affected Service
- **Service:** Apache2 + Drupal 7.31 + phpMyAdmin
- **Port:** 80/TCP
- **Paths:** `/drupal/install.php`, `/phpmyadmin/setup/index.php`

## Vulnerable Configuration
After installation neither Drupal nor phpMyAdmin denies access to their installer
pages. Apache serves them to all clients without restriction:

```
# No <Location> or <Files> block protecting installer endpoints
# GET /drupal/install.php    -> 200 OK
# GET /phpmyadmin/setup/     -> 200 OK
```

## Remediation Steps
1. Add an Apache `<Location>` block (or equivalent `<Files>`) to the Drupal/phpMyAdmin
   virtual host or `.htaccess`, returning 403 for the installer paths:

   ```apache
   <Location /drupal/install.php>
       Require all denied
   </Location>

   <Location /phpmyadmin/setup>
       Require all denied
   </Location>
   ```

   For Apache 2.2 syntax replace `Require all denied` with:
   ```apache
   Order deny,allow
   Deny from all
   ```

2. Reload Apache:
   ```
   service apache2 reload
   ```

3. Verify that `curl -o /dev/null -w '%{http_code}' localhost/drupal/install.php`
   returns `403` and that `curl localhost/drupal/` still returns `200`.

## Build

Build from the `meta3/ubuntu/` directory (one level above this scenario):

```
docker build -f scenario-05/Dockerfile -t meta3u-s05 .
docker run -d --name meta3u-s05 -p 8080:80 meta3u-s05
docker exec meta3u-s05 /bin/bash /verify.sh
docker stop meta3u-s05 && docker rm meta3u-s05
```
