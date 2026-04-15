# WordPress 4.7.1 — Weak `admin:admin` Credentials + Unpatched Core

## Severity
**Critical** (CVSS 9.8 via chained auth-bypass / RCE in 4.7.x)

## CVE
- **CVE-2017-1001000** — 4.7.0 / 4.7.1 REST API unauthenticated content injection
  (privilege escalation to post edit, often chained to RCE via plugin upload).
- **CVE-2016-10033 / CVE-2016-10045** — PHPMailer RCE reachable from WordPress
  `wp-mail.php` on this version (and the reason 4.7.2 was released as an emergency).
- Weak default credentials `admin / admin` compound every one of the above by
  trivially granting direct admin-panel access even without an exploit.

## Description
The upstream metasploitable3-windows build ships WordPress 4.7.1 on WampServer 3.0.6
with a pre-populated administrator account using the password **`admin`**. Any
unauthenticated attacker that can reach the HTTP listener can either:

1. Log in directly at `/wp-login.php` with `admin:admin` and push a PHP-capable
   plugin (`shell.php`) to obtain RCE as the Apache service user, or
2. Abuse the 4.7.0/4.7.1 REST API content-injection bug (CVE-2017-1001000) to
   overwrite any post and, combined with a shortcode-evaluating theme, pivot to RCE
   without credentials at all.

Both attacks are publicly automated (Metasploit `wp_admin_shell_upload`, WPScan
`--passwords rockyou.txt`, the REST-API PoC in exploit-db 41223).

## Affected Service
- **Service:** Apache 2.4 hosting `C:\wamp\www\wordpress` (WordPress 4.7.1)
- **Port:** 80/TCP
- **Backing store:** MariaDB 10.1 on 3306/TCP (local only)

## Vulnerable Configuration
```
WordPress core version : 4.7.1
Admin user             : admin
Admin password         : admin
REST API               : enabled, unauthenticated
```

## Remediation Steps
The verifier accepts any of the following; the first two are the real-world fix.

1. **Update WordPress core** to 4.7.2 or later (4.9.8+ strongly preferred, or the
   current 6.x line):
   ```powershell
   # from C:\wamp\www\wordpress
   php wp-cli.phar core update --version=4.9.8
   ```
2. **Rotate the admin password** to something not in any wordlist:
   ```powershell
   php wp-cli.phar user update admin --user_pass='<long-random>'
   ```
3. **Defense-in-depth:** disable XML-RPC (`xmlrpc.php`), restrict `/wp-login.php` and
   `/wp-admin/` by source IP at the Apache layer, and front the site with a WAF that
   blocks the known CVE-2017-1001000 request shape.
