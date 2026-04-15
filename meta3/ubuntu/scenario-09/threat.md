# jQuery < 1.9.0 XSS in Drupal-Shipped Assets (CVE-2012-6708)

## Severity
**Medium** (CVSS 6.1)

## CVE
CVE-2012-6708

## Description
Drupal 7.31 ships jQuery 1.4.4 at `/drupal/misc/jquery.js`. jQuery versions
before 1.9.0 are vulnerable to a cross-site scripting flaw in the `$.html()`
selector function: when a string beginning with a hash character is passed as a
selector, jQuery evaluates it as HTML rather than as a DOM query. An attacker
can craft a URL or inject a fragment identifier that causes arbitrary JavaScript
to execute in the context of the Drupal application origin.

The vulnerable code path is:
```javascript
// jQuery < 1.9.0: this evaluates user-supplied HTML
$( location.hash )
```

Any page on the Drupal site that passes `location.hash` or a user-controlled
string to a jQuery selector is exploitable. Attackers can steal session cookies,
perform actions as the authenticated user, or redirect the browser to a phishing
page.

## Affected Service
- **Service:** Apache2 + Drupal 7.31
- **Port:** 80/TCP
- **Asset:** `/drupal/misc/jquery.js`

## Vulnerable Configuration
```
/var/www/html/drupal/misc/jquery.js — jQuery 1.4.4
```
The bundled jQuery version can be confirmed with:
```bash
head -3 /var/www/html/drupal/misc/jquery.js
# jQuery JavaScript Library v1.4.4
```

## Remediation Steps
1. Replace the bundled jQuery with version 1.9.0 or later. The minimal in-place
   fix replaces only `misc/jquery.js` and the minified map (if present):

   ```bash
   cd /var/www/html/drupal/misc
   wget -O jquery.js \
     https://code.jquery.com/jquery-1.9.0.min.js
   ```

2. If the Drupal site uses the jQuery Update module, enable and configure it
   to serve a patched version:
   ```bash
   drush en jquery_update -y
   drush vset jquery_update_jquery_version 1.10
   ```

3. Verify the version string is >= 1.9.0:
   ```bash
   head -3 /var/www/html/drupal/misc/jquery.js | grep -E 'v1\.[0-8]\.'
   # Must produce no output
   ```

## Build

Build from the `meta3/ubuntu/` directory (one level above this scenario):

```
docker build -f scenario-09/Dockerfile -t meta3u-s09 .
docker run -d --name meta3u-s09 -p 8080:80 meta3u-s09
docker exec meta3u-s09 /bin/bash /verify.sh
docker stop meta3u-s09 && docker rm meta3u-s09
```
