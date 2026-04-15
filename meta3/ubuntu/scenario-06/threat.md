# Drupal 7.x SQL Injection leading to Remote Code Execution (Drupalgeddon)

## Severity
**Critical** (CVSS 9.3)

## CVE
CVE-2014-3704 ("Drupalgeddon")

## Description
Drupal 7.31 contains a SQL injection vulnerability in the database abstraction
layer. The `expandArguments()` function in `includes/database/database.inc`
does not properly sanitize array keys supplied in query placeholders. An
unauthenticated attacker can craft an HTTP POST request to `/drupal/?q=node`
that injects arbitrary SQL into the underlying MySQL database.

Because Drupal's form system evaluates PHP callbacks stored in the database, a
successful injection can insert a row that registers a malicious PHP function as
a post-render callback, achieving unauthenticated remote code execution before
any authentication check runs.

The payload shape is:
```
POST /drupal/?q=node&destination=node
name[0%20;UPDATE+users+SET+name%3d'backdoor'...]=foo
```

## Affected Service
- **Service:** Apache2 + Drupal 7.31
- **Port:** 80/TCP
- **Path:** `/drupal/`
- **File:** `/var/www/html/drupal/includes/database/database.inc`

## Vulnerable Configuration
Drupal version 7.31 ships with the unpatched `expandArguments()` function.
The issue was fixed in 7.32, released 15 October 2014.

## Remediation Steps
1. Upgrade Drupal core to 7.32 or later. The canonical in-place method is:

   ```bash
   cd /var/www/html/drupal
   drush up drupal
   ```

   Or manually:
   ```bash
   cd /tmp
   wget https://ftp.drupal.org/files/projects/drupal-7.32.tar.gz
   tar xzf drupal-7.32.tar.gz
   cp -r drupal-7.32/includes/database/. /var/www/html/drupal/includes/database/
   ```

2. Confirm the patch is applied by checking the version string in
   `/var/www/html/drupal/CHANGELOG.txt` or:
   ```bash
   grep 'Drupal 7\.3[2-9]\|Drupal 7\.[4-9]' /var/www/html/drupal/CHANGELOG.txt
   ```

3. Send the Drupalgeddon payload — it must not execute:
   ```bash
   curl -X POST 'http://localhost/drupal/?q=node&destination=node' \
     --data 'name[0%20;UPDATE+users+SET+name%3dtest+WHERE+uid%3d1;%23]=foo&pass=foo&form_id=user_login_block'
   ```
   The response must not contain a 200 with signs of SQL execution. The
   Drupal homepage must remain accessible.

## Build

Build from the `meta3/ubuntu/` directory (one level above this scenario):

```
docker build -f scenario-06/Dockerfile -t meta3u-s06 .
docker run -d --name meta3u-s06 -p 8080:80 meta3u-s06
docker exec meta3u-s06 /bin/bash /verify.sh
docker stop meta3u-s06 && docker rm meta3u-s06
```
