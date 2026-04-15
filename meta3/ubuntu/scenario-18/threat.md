# Drupal web.config Sensitive File Disclosure via Apache

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory
- OpenVAS: "Sensitive File Disclosure (HTTP)" — `/drupal/web.config`

## Description
Metasploitable 3's Drupal installation includes a `web.config` file in the
Drupal root (`/var/www/html/drupal/web.config`). This file is an IIS URL
Rewrite configuration artifact that is bundled with the Drupal distribution for
use on Windows/IIS deployments. On Apache it has no functional role but Apache
serves it as a plain XML file to any client that requests it.

The `web.config` file reveals:
- The internal URL rewrite rules and application routing structure
- PHP file mappings and handler configurations
- Path-disclosure information that aids further enumeration and exploitation

An attacker performing reconnaissance can retrieve this file unauthenticated,
gaining an accurate map of the application's internal URL structure. On some
deployments `web.config` may also contain database connection strings or other
sensitive attributes.

## Affected Service
- **Service:** Apache2 + Drupal 7.31
- **Port:** 80/TCP
- **Path:** `/drupal/web.config`
- **File on disk:** `/var/www/html/drupal/web.config`

## Vulnerable Configuration
Apache has no rule denying access to `.config` extension files:
```
# GET /drupal/web.config -> 200 OK (file served in full)
```

## Remediation Steps
1. Add a `<FilesMatch>` directive to the Apache virtual host or Drupal's
   `.htaccess` to deny access to `.config` extension files:

   **Apache 2.4 syntax:**
   ```apache
   <FilesMatch "\.config$">
       Require all denied
   </FilesMatch>
   ```

   **Apache 2.2 syntax:**
   ```apache
   <FilesMatch "\.config$">
       Order deny,allow
       Deny from all
   </FilesMatch>
   ```

   Place this block in `/etc/apache2/sites-enabled/000-default.conf` inside
   the `<VirtualHost>` stanza, or add it to
   `/var/www/html/drupal/.htaccess`.

2. Reload Apache:
   ```bash
   service apache2 reload
   ```

3. Verify that `curl localhost/drupal/web.config` returns 403 and that
   `curl localhost/drupal/` still returns 200.

## Build

Build from the `meta3/ubuntu/` directory (one level above this scenario):

```
docker build -f scenario-18/Dockerfile -t meta3u-s18 .
docker run -d --name meta3u-s18 -p 8080:80 meta3u-s18
docker exec meta3u-s18 /bin/bash /verify.sh
docker stop meta3u-s18 && docker rm meta3u-s18
```
