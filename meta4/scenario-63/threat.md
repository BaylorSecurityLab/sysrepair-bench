# Roundcube 1.6.3 — SVG-Based Stored XSS (CVE-2023-5631)

## Severity
**Medium** (CVSS 6.1)

## CVE / CWE
- CVE-2023-5631
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## Description
Roundcube 1.6.3 does not adequately sanitize SVG elements embedded in HTML
email messages. When a victim opens a crafted email containing a malicious SVG
payload, the SVG is rendered inline in the browser within the Roundcube web
interface. SVG supports embedded JavaScript via event handlers and `<script>`
tags, which execute in the context of the Roundcube origin. An attacker who
can send email to a Roundcube user can therefore execute arbitrary JavaScript
in the victim's browser session, enabling session hijacking, credential theft,
or unauthorized email actions.

This vulnerability is stored (persistent) — the payload is saved in the
mail server and fires every time the victim opens or previews the email.

## Affected Service
- **Service:** Roundcube 1.6.3 (Apache)
- **Port:** 80/TCP (HTTP)
- **Vulnerable component:** HTML email renderer — SVG element handling

## Vulnerable Configuration
- Roundcube 1.6.3 with default configuration renders SVG content from HTML
  emails without stripping potentially malicious SVG elements
- No Content-Security-Policy header is set by default

## Remediation Steps (Compensating Controls — no upgrade)
1. Add a `Content-Security-Policy` response header in Apache configuration to
   block inline script execution. In `/etc/apache2/sites-available/000-default.conf`
   or a `.htaccess` file in the Roundcube document root:
   ```
   Header always set Content-Security-Policy "default-src 'self'; script-src 'self'"
   ```
   Ensure `mod_headers` is enabled:
   ```
   a2enmod headers
   ```
2. Configure Roundcube to strip SVG and other dangerous HTML elements by
   setting in `/var/www/html/config/config.inc.php`:
   ```php
   $config['htmleditor'] = 0;
   $config['show_images'] = 0;
   ```
3. Reload Apache to apply header changes:
   ```
   apache2ctl graceful
   ```
4. Verify the CSP header is present in responses:
   ```
   curl -I http://localhost/ | grep -i content-security-policy
   ```
