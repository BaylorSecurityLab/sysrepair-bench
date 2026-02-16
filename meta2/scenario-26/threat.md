# Apache httpOnly Cookie Information Disclosure

## Severity
**Medium** (CVSS 4.3)

## CVE
N/A (configuration weakness)

## Description
The Apache 2.2 web server on this system does not set the `HttpOnly` and `Secure` flags
on cookies in its responses. Without the `HttpOnly` flag, cookies are accessible to
client-side JavaScript, which means a Cross-Site Scripting (XSS) vulnerability could be
used to steal session cookies and hijack user sessions. Without the `Secure` flag, cookies
may be transmitted over unencrypted HTTP connections, exposing them to network sniffing.

Apache 2.2's default configuration does not include any `Header` directives to append
these security flags to `Set-Cookie` headers. The `mod_usertrack` module, when enabled,
sets tracking cookies without these protections.

## Affected Service
- **Service:** Apache HTTP Server 2.2
- **Port:** 80/TCP
- **Binary:** /usr/sbin/apache2
- **Configuration:** /etc/apache2/apache2.conf, /etc/apache2/conf.d/

## Vulnerable Configuration
The default Apache configuration has no `Header` directives to enforce cookie security:

```
# No cookie security headers configured
# mod_headers is not loaded or has no Set-Cookie rules
# Cookies set by any module or application lack HttpOnly and Secure flags
```

The `mod_usertrack` configuration sets cookies without protection:
```
<IfModule mod_usertrack.c>
    CookieTracking on
    CookieName Apache_Track
    # No HttpOnly or Secure flags
</IfModule>
```

## Remediation Steps
1. Enable the `mod_headers` module:
   ```
   a2enmod headers
   ```
2. Add cookie security headers to the Apache configuration (e.g.,
   `/etc/apache2/conf.d/security` or the main config):
   ```
   Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure
   ```
   Or alternatively:
   ```
   Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure"
   ```
3. Optionally add additional security headers:
   ```
   Header always append X-Frame-Options DENY
   Header always set X-Content-Type-Options nosniff
   ```
4. Restart Apache:
   ```
   apache2ctl restart
   ```
5. Verify by inspecting response headers with `curl -I` and confirming cookies
   include `HttpOnly` and `Secure` flags.
