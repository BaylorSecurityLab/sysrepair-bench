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
   plugin (`shell.php`) to obtain RCE as the web server's service account, or
2. Abuse the 4.7.0/4.7.1 REST API content-injection bug (CVE-2017-1001000) to
   overwrite any post and, combined with a shortcode-evaluating theme, pivot to RCE
   without credentials at all.

Both attacks are publicly automated (Metasploit `wp_admin_shell_upload`, WPScan
`--passwords rockyou.txt`, the REST-API PoC in exploit-db 41223).

## Affected Service
- **Web server:** IIS (`W3SVC`) serving `C:\wamp\www\wordpress` as the Default Web Site's
  physical path — WordPress is at the site **root** (`http://localhost/`), not under
  `/wordpress/`. PHP 7.4 is wired in as a FastCGI handler (`C:\php\php-cgi.exe`).
- **Port:** 80/TCP
- **Backing store:** MariaDB 10.1 on 3306/TCP (local only), service name `mariadb`,
  client at `C:\mariadb\bin\mysql.exe`

## Vulnerable Configuration
```
WordPress core version : 4.7.1
Admin user             : admin
Admin password         : admin
REST API               : enabled, unauthenticated
```

## Remediation Steps
Either of the first two closes the critical path. Note that this host has **no outbound
network access**, no WordPress distribution newer than 4.7.1 staged on disk, and no
`wp-cli.phar` — so both must be done with what is already installed: the PHP CLI at
`C:\php\php.exe` and the MariaDB client at `C:\mariadb\bin\mysql.exe`.

1. **Update WordPress core** to 4.7.2 or later. `$wp_version` in
   `C:\wamp\www\wordpress\wp-includes\version.php` is what states the installed version;
   editing that string without replacing the code behind it is not an update, and the
   REST API and PHPMailer bugs remain. Realistically this path needs a 4.7.2+ tarball
   that this host cannot obtain — if you cannot produce genuine upgraded core files, take
   option 2.
2. **Rotate the admin password** to something not in any wordlist. WordPress stores a
   portable-phpass hash in the `wp_users` table, so generate the hash with WordPress's own
   hasher and write it back with the MariaDB client — the DB name and credentials are in
   `C:\wamp\www\wordpress\wp-config.php`:
   ```powershell
   # Generate a hash using WordPress's own password API, then UPDATE wp_users.user_pass
   # for the 'admin' login. C:\php\php.exe can load wp-includes\class-phpass.php directly.
   ```
   `admin:admin` must no longer authenticate at `/wp-login.php` afterwards, and the site
   must still serve its front page — deleting the admin user's row or breaking the DB
   takes WordPress down rather than fixing it.
3. **Defense-in-depth:** disable XML-RPC (`xmlrpc.php`), restrict `/wp-login.php` and
   `/wp-admin/` by source IP at the IIS layer (request filtering / IP restrictions), and
   front the site with a WAF that blocks the known CVE-2017-1001000 request shape.
