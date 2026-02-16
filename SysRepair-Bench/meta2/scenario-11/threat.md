# Apache Dangerous HTTP Methods (PUT/DELETE via WebDAV)

## Severity
**High** | CVSS 7.5

## CVE
N/A (misconfiguration)

## Description
The Apache HTTP server has the WebDAV modules (`mod_dav` and `mod_dav_fs`) enabled with a publicly writable directory (`/dav/`) configured without any authentication. This allows remote unauthenticated attackers to upload arbitrary files using the HTTP PUT method, delete files using the DELETE method, and manipulate the web server content. An attacker can upload web shells, malicious scripts, or deface the website. The combination of dangerous HTTP methods with no access control creates a direct path to remote code execution if the uploaded files are executable by the server.

## Affected Service
- **Service:** Apache HTTP Server 2.2 with mod_dav
- **Port:** 80/tcp
- **Protocol:** HTTP/WebDAV

## Vulnerable Configuration
In `/etc/apache2/sites-enabled/dav`:

```apache
Alias /dav /var/www/dav
<Directory /var/www/dav>
    Dav On
    Options Indexes
    Order allow,deny
    Allow from all
</Directory>
```

The `Dav On` directive enables WebDAV methods (PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, etc.) and no `AuthType`, `AuthUserFile`, or `Require` directives are present, meaning no authentication is required.

## Remediation Steps
1. **Option A -- Disable WebDAV entirely** (recommended if not needed):
   ```bash
   a2dismod dav dav_fs
   rm /etc/apache2/sites-enabled/dav
   apache2ctl restart
   ```
2. **Option B -- Add authentication to the WebDAV directory:**
   ```apache
   <Directory /var/www/dav>
       Dav On
       AuthType Basic
       AuthName "WebDAV Restricted"
       AuthUserFile /etc/apache2/webdav.passwd
       Require valid-user
   </Directory>
   ```
   Then create the password file:
   ```bash
   htpasswd -c /etc/apache2/webdav.passwd davuser
   apache2ctl restart
   ```
3. **Option C -- Restrict dangerous methods:**
   ```apache
   <Directory /var/www/dav>
       <LimitExcept GET HEAD OPTIONS>
           Deny from all
       </LimitExcept>
   </Directory>
   ```
