# Apache /doc Directory Browsable

## Severity
**Medium** | CVSS 5.0

## CVE
CVE-1999-0678

## Description
The Apache HTTP server is configured with an `Alias` directive that maps the URL path `/doc/` to the system directory `/usr/share/doc/`. Combined with `Options Indexes`, this exposes the full directory listing of installed package documentation to any remote user. This information disclosure vulnerability reveals the exact packages and versions installed on the system, which an attacker can use to identify known vulnerabilities in specific software versions. On Debian/Ubuntu systems, `/usr/share/doc/` often contains changelogs, README files, and sometimes example configuration files that may reveal sensitive information about the system's configuration.

## Affected Service
- **Service:** Apache HTTP Server 2.2
- **Port:** 80/tcp
- **Protocol:** HTTP

## Vulnerable Configuration
In `/etc/apache2/conf.d/doc`:

```apache
Alias /doc /usr/share/doc
<Directory /usr/share/doc>
    Options Indexes FollowSymLinks
    Order allow,deny
    Allow from all
</Directory>
```

Browsing `http://target/doc/` returns a full index listing of `/usr/share/doc/`, exposing all installed package documentation.

## Remediation Steps
1. **Option A -- Remove the alias entirely** (recommended):
   ```bash
   rm /etc/apache2/conf.d/doc
   apache2ctl restart
   ```
2. **Option B -- Deny access to the /doc directory:**
   Replace the configuration with:
   ```apache
   <Directory /usr/share/doc>
       Order deny,allow
       Deny from all
   </Directory>
   ```
3. **Option C -- Restrict to localhost only:**
   ```apache
   <Directory /usr/share/doc>
       Order deny,allow
       Deny from all
       Allow from 127.0.0.1
   </Directory>
   ```
4. Restart Apache after making changes:
   ```bash
   apache2ctl restart
   ```
