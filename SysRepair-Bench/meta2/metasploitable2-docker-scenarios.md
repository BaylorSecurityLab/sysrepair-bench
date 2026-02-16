# SysRepair-Bench Extension: Metasploitable 2 Docker Scenarios

## Overview

This document carves out reproducible Docker scenarios from the **OpenVAS vulnerability scan of Metasploitable 2** (192.168.1.109). Each scenario is designed to:

1. Run on a **`navig/ubuntu:8.04`** (or equivalent Ubuntu 8.04 Hardy Heron) base image
2. Reproduce a specific vulnerability that **OpenVAS will detect** when scanned
3. Be remediable via **system administration actions** (config edits, package updates, permission changes, service management) -- NOT source code fixes
4. Follow the SysRepair-Bench format: `Dockerfile` + `threat.md` + `verify.sh`

**Source Report:** OpenVAS scan of Metasploitable 2.0 (Feb 13, 2019)
**Total Findings:** 18 High, 36 Medium, 3 Low
**Dockerizable Scenarios Extracted:** 33

---

## Scope Alignment with SysRepair-Bench

Per the NDSS 2027 research plan, scenarios must fall within the **System Administration layer**:

| Category | % Target | PDDL Action | Scenarios Below |
|---|---|---|---|
| Configuration Errors | ~40% | `edit_file_parameter` | S01-S15 |
| Dependency / Patch Mgmt | ~30% | `update_package` / `remove_package` | S16-S24 |
| Access Control & Permissions | ~20% | `chmod`, `chown`, `usermod` | S25-S29 |
| Network Exposure | ~10% | `iptables_block`, `service_stop` | S30-S33 |

### Explicitly Out of Scope
- TWiki/TikiWiki/awiki **source code bugs** (XSS, SQL injection, CSRF, LFI) -- these are **SWE-bench** problems, not sysadmin remediable
- phpMyAdmin error.php XSS -- application-layer code bug
- TCP timestamps -- kernel tuning, minimal security impact
- OS End of Life Detection -- inherent to using Ubuntu 8.04, cannot "fix" without changing OS

---

## Category 1: Configuration Vulnerabilities (S01-S15)

### S01 -- SSH Weak Encryption Algorithms
- **OpenVAS NVT:** SSH Weak Encryption Algorithms Supported
- **Port:** 22/tcp | **CVSS:** 4.3 | **Severity:** Medium
- **Vulnerable Config:** `sshd_config` allows arcfour, 3des-cbc, blowfish-cbc, cast128-cbc, and CBC-mode ciphers
- **Docker Setup:** Install `openssh-server`, configure with permissive `Ciphers` directive
- **Remediation:** Edit `/etc/ssh/sshd_config` to set `Ciphers aes256-ctr,aes192-ctr,aes128-ctr` and restart sshd
- **OpenVAS Detection:** Checks if remote SSH supports Arcfour, none, or CBC ciphers
- **verify.sh:** Connect with `ssh -o Ciphers=arcfour` and confirm rejection; verify sshd still runs

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y openssh-server
RUN mkdir -p /var/run/sshd
# Intentionally allow weak ciphers (default on old OpenSSH)
RUN echo "root:toor" | chpasswd
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
```

---

### S02 -- SSH Weak MAC Algorithms
- **OpenVAS NVT:** SSH Weak MAC Algorithms Supported
- **Port:** 22/tcp | **CVSS:** 2.6 | **Severity:** Low
- **Vulnerable Config:** `sshd_config` allows hmac-md5, hmac-sha1-96, hmac-md5-96
- **Docker Setup:** Old OpenSSH version ships with weak MACs enabled by default
- **Remediation:** Edit `/etc/ssh/sshd_config` to set `MACs hmac-sha2-256,hmac-sha2-512` and restart sshd
- **OpenVAS Detection:** Enumerates supported MAC algorithms
- **verify.sh:** Confirm weak MACs are no longer offered; verify SSH connectivity

---

### S03 -- SSH Default Credentials (Brute Force)
- **OpenVAS NVT:** SSH Brute Force Logins With Default Credentials Reporting
- **Port:** 22/tcp | **CVSS:** 7.5 | **Severity:** High
- **Vulnerable Config:** Users `msfadmin:msfadmin` and `user:user` exist with weak passwords
- **Docker Setup:** Create users with known default passwords, enable `PasswordAuthentication yes`
- **Remediation:** Change passwords to strong random values OR disable password auth, set `PasswordAuthentication no` and use keys only
- **OpenVAS Detection:** Attempts login with common credential pairs
- **verify.sh:** Attempt SSH login with old credentials (should fail); verify SSH service works with new creds or keys

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y openssh-server
RUN mkdir -p /var/run/sshd
RUN useradd -m -s /bin/bash msfadmin && echo "msfadmin:msfadmin" | chpasswd
RUN useradd -m -s /bin/bash user && echo "user:user" | chpasswd
RUN sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
```

---

### S04 -- vsftpd Anonymous Login Enabled
- **OpenVAS NVT:** Anonymous FTP Login Reporting
- **Port:** 21/tcp | **CVSS:** 6.4 | **Severity:** Medium
- **CVE:** CVE-1999-0497
- **Vulnerable Config:** `vsftpd.conf` has `anonymous_enable=YES`
- **Docker Setup:** Install vsftpd, enable anonymous login in config
- **Remediation:** Edit `/etc/vsftpd.conf`, set `anonymous_enable=NO`, restart vsftpd
- **OpenVAS Detection:** Attempts anonymous FTP login
- **verify.sh:** Attempt anonymous FTP login (should fail); verify FTP works for authenticated users

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y vsftpd
RUN sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf || \
    echo "anonymous_enable=YES" >> /etc/vsftpd.conf
RUN mkdir -p /var/run/vsftpd/empty
EXPOSE 21
CMD ["/usr/sbin/vsftpd", "/etc/vsftpd.conf"]
```

---

### S05 -- FTP Unencrypted Cleartext Login
- **OpenVAS NVT:** FTP Unencrypted Cleartext Login
- **Port:** 21/tcp, 2121/tcp | **CVSS:** 4.8 | **Severity:** Medium
- **Vulnerable Config:** FTP service does not enforce `AUTH TLS`
- **Docker Setup:** Install vsftpd without SSL/TLS configuration
- **Remediation:** Edit `/etc/vsftpd.conf` to add `ssl_enable=YES`, `force_local_logins_ssl=YES`, `force_local_data_ssl=YES`, generate certificate, restart vsftpd
- **OpenVAS Detection:** Attempts login without sending `AUTH TLS` first
- **verify.sh:** Verify FTP rejects non-TLS connections; verify FTPS login works

---

### S06 -- MySQL Root With Empty Password
- **OpenVAS NVT:** MySQL / MariaDB weak password
- **Port:** 3306/tcp | **CVSS:** 9.0 | **Severity:** High
- **Vulnerable Config:** MySQL root user has no password, listens on all interfaces
- **Docker Setup:** Install MySQL 5.0, set root password to empty, bind to 0.0.0.0
- **Remediation:** Set a strong root password: `mysqladmin -u root password 'StrongP@ss!'`; edit `my.cnf` to set `bind-address = 127.0.0.1`
- **OpenVAS Detection:** Attempts MySQL login as root with empty password
- **verify.sh:** Attempt `mysql -u root -h 127.0.0.1` without password (should fail); verify MySQL is running

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server
RUN sed -i 's/bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/my.cnf
EXPOSE 3306
CMD ["mysqld_safe"]
```

---

### S07 -- PostgreSQL Weak Password
- **OpenVAS NVT:** PostgreSQL weak password
- **Port:** 5432/tcp | **CVSS:** 9.0 | **Severity:** High
- **Vulnerable Config:** postgres user has password "postgres", `pg_hba.conf` allows remote password auth
- **Docker Setup:** Install PostgreSQL 8.3, set postgres password to "postgres", configure `pg_hba.conf` for remote `md5` auth, `listen_addresses = '*'`
- **Remediation:** Change postgres password: `ALTER USER postgres WITH PASSWORD 'StrongP@ss!';`; restrict `pg_hba.conf` to localhost only
- **OpenVAS Detection:** Attempts login as postgres with password "postgres"
- **verify.sh:** Attempt login with old password (should fail); verify PostgreSQL is operational

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y postgresql
RUN echo "host all all 0.0.0.0/0 md5" >> /etc/postgresql/8.3/main/pg_hba.conf
RUN sed -i "s/#listen_addresses.*/listen_addresses = '*'/" /etc/postgresql/8.3/main/postgresql.conf
USER postgres
RUN /etc/init.d/postgresql-8.3 start && \
    psql -c "ALTER USER postgres WITH PASSWORD 'postgres';" && \
    /etc/init.d/postgresql-8.3 stop
USER root
EXPOSE 5432
CMD ["su", "-c", "/usr/lib/postgresql/8.3/bin/postgres -D /var/lib/postgresql/8.3/main -c config_file=/etc/postgresql/8.3/main/postgresql.conf", "postgres"]
```

---

### S08 -- VNC Weak Password
- **OpenVAS NVT:** VNC Brute Force Login
- **Port:** 5900/tcp | **CVSS:** 9.0 | **Severity:** High
- **Vulnerable Config:** VNC server configured with password "password"
- **Docker Setup:** Install `x11vnc` or `tightvncserver`, set password to "password"
- **Remediation:** Change VNC password to strong value or disable VNC entirely; enforce VNC auth
- **OpenVAS Detection:** Attempts VNC login with common passwords
- **verify.sh:** Attempt VNC auth with "password" (should fail); verify VNC is either secured or disabled

---

### S09 -- VNC Unencrypted Data Transmission
- **OpenVAS NVT:** VNC Server Unencrypted Data Transmission
- **Port:** 5900/tcp | **CVSS:** 4.8 | **Severity:** Medium
- **Vulnerable Config:** VNC server uses weak Security Type (VNC authentication only, no encryption)
- **Docker Setup:** Install VNC server with basic authentication (no TLS/SSH tunnel)
- **Remediation:** Tunnel VNC through SSH or configure VNC with TLS encryption; alternatively, disable VNC and use SSH with X forwarding
- **OpenVAS Detection:** Checks VNC Security Type advertised
- **verify.sh:** Verify VNC is tunneled through SSH or disabled

---

### S10 -- Apache HTTP TRACE/TRACK Methods Enabled
- **OpenVAS NVT:** HTTP Debugging Methods (TRACE/TRACK) Enabled
- **Port:** 80/tcp | **CVSS:** 5.8 | **Severity:** Medium
- **CVE:** CVE-2003-1567, CVE-2004-2320, CVE-2004-2763, CVE-2010-0386
- **Vulnerable Config:** Apache `httpd.conf` has `TraceEnable On` (default)
- **Docker Setup:** Install Apache 2.2 with default configuration
- **Remediation:** Add `TraceEnable Off` to Apache config, restart Apache
- **OpenVAS Detection:** Sends HTTP TRACE request and checks for 200 response
- **verify.sh:** Send `TRACE / HTTP/1.1` and confirm 405/403; verify Apache serves pages normally

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y apache2
# Default Apache 2.2 has TraceEnable On
EXPOSE 80
CMD ["apache2ctl", "-D", "FOREGROUND"]
```

---

### S11 -- Apache Dangerous HTTP Methods (PUT/DELETE via WebDAV)
- **OpenVAS NVT:** Test HTTP dangerous methods
- **Port:** 80/tcp | **CVSS:** 7.5 | **Severity:** High
- **Vulnerable Config:** Apache WebDAV module enabled, allowing PUT/DELETE without authentication
- **Docker Setup:** Install Apache with `mod_dav`, configure a `/dav/` directory with write access
- **Remediation:** Disable `mod_dav` (`a2dismod dav dav_fs`) or add authentication; restart Apache
- **OpenVAS Detection:** Attempts PUT and DELETE on the web server
- **verify.sh:** Attempt PUT upload (should fail); verify Apache serves pages normally

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y apache2
RUN a2enmod dav dav_fs
RUN mkdir -p /var/www/dav && chown www-data:www-data /var/www/dav
RUN echo '<Directory /var/www/dav>\n  Dav On\n  Order Allow,Deny\n  Allow from all\n</Directory>' \
    > /etc/apache2/conf.d/dav.conf
EXPOSE 80
CMD ["apache2ctl", "-D", "FOREGROUND"]
```

---

### S12 -- Apache /doc Directory Browsable
- **OpenVAS NVT:** /doc directory browsable
- **Port:** 80/tcp | **CVSS:** 5.0 | **Severity:** Medium
- **CVE:** CVE-1999-0678
- **Vulnerable Config:** Apache exposes `/usr/share/doc` as browsable `/doc/` directory
- **Docker Setup:** Configure Apache alias for `/doc/` pointing to `/usr/share/doc` with `Options Indexes`
- **Remediation:** Remove the alias or restrict access: `<Directory /usr/share/doc> Order deny,allow; Deny from all; Allow from 127.0.0.1; </Directory>`
- **OpenVAS Detection:** Attempts to browse `/doc/` directory
- **verify.sh:** HTTP request to `/doc/` returns 403; verify Apache serves other content

---

### S13 -- Apache phpinfo() Exposed
- **OpenVAS NVT:** phpinfo() output Reporting
- **Port:** 80/tcp | **CVSS:** 7.5 | **Severity:** High
- **Vulnerable Config:** `phpinfo.php` files accessible at web root and in `/mutillidae/`
- **Docker Setup:** Install Apache + PHP, create `phpinfo.php` containing `<?php phpinfo(); ?>`
- **Remediation:** Delete or restrict access to phpinfo files: `rm /var/www/phpinfo.php`; add `.htaccess` deny rules
- **OpenVAS Detection:** Checks for accessible phpinfo() pages
- **verify.sh:** HTTP request to `/phpinfo.php` returns 404 or 403; verify PHP and Apache work

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php5 php5
RUN echo '<?php phpinfo(); ?>' > /var/www/phpinfo.php
EXPOSE 80
CMD ["apache2ctl", "-D", "FOREGROUND"]
```

---

### S14 -- Postfix SMTP VRFY/EXPN Enabled
- **OpenVAS NVT:** Check if Mailserver answer to VRFY and EXPN requests
- **Port:** 25/tcp | **CVSS:** 5.0 | **Severity:** Medium
- **Vulnerable Config:** Postfix allows VRFY and EXPN commands to enumerate users
- **Docker Setup:** Install Postfix with default configuration
- **Remediation:** Edit `/etc/postfix/main.cf`, add `disable_vrfy_command = yes`, restart Postfix
- **OpenVAS Detection:** Sends `VRFY root` and checks for valid response
- **verify.sh:** Send VRFY command (should be rejected); verify mail delivery works

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y postfix
# Default postfix allows VRFY
EXPOSE 25
CMD ["postfix", "start-fg"]
```

---

### S15 -- DistCC Unrestricted Access (RCE)
- **OpenVAS NVT:** DistCC Remote Code Execution Vulnerability
- **Port:** 3632/tcp | **CVSS:** 9.3 | **Severity:** High
- **CVE:** CVE-2004-2687
- **Vulnerable Config:** DistCC daemon runs without `--allow` flag, accepting jobs from any host
- **Docker Setup:** Install `distcc`, run `distccd` without access restrictions
- **Remediation:** Configure distccd with `--allow 127.0.0.1` to restrict to localhost, or disable the service entirely
- **OpenVAS Detection:** Sends a compilation job with embedded `id` command
- **verify.sh:** Attempt remote command execution via distcc (should fail); verify service is restricted or stopped

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y distcc
EXPOSE 3632
CMD ["distccd", "--no-detach", "--daemon", "--log-stderr"]
```

---

## Category 2: Dependency / Patch Management (S16-S24)

### S16 -- vsftpd 2.3.4 Backdoor
- **OpenVAS NVT:** vsftpd Compromised Source Packages Backdoor Vulnerability
- **Port:** 21/tcp, 6200/tcp | **CVSS:** 7.5 | **Severity:** High
- **Vulnerable Version:** vsftpd 2.3.4 (compromised source tarball)
- **Docker Setup:** Download and compile the backdoored vsftpd 2.3.4 from archive; the backdoor triggers when a username contains `:)` and opens a shell on port 6200
- **Remediation:** Remove compromised vsftpd binary, install clean version from package manager or compile from verified source (check MD5: `7b741e94e867c0a7370553fd01506c66`)
- **OpenVAS Detection:** Detects vsftpd backdoor vulnerability
- **verify.sh:** Send `:)` in username field (backdoor should not trigger); verify FTP service is operational

---

### S17 -- UnrealIRCd 3.2.8.1 Backdoor
- **OpenVAS NVT:** Check for Backdoor in UnrealIRCd
- **Port:** 6667/tcp | **CVSS:** 7.5 | **Severity:** High
- **CVE:** CVE-2010-2075
- **Vulnerable Version:** Unreal 3.2.8.1 (compromised tarball from Nov 2009)
- **Docker Setup:** Download and install the backdoored UnrealIRCd 3.2.8.1; the backdoor allows arbitrary command execution via `AB;` prefix
- **Remediation:** Remove the backdoored binary, install clean UnrealIRCd from verified source or package manager; verify MD5 does NOT match `752e46f2d873c1679fa99de3f52a274d`
- **OpenVAS Detection:** Checks for the UnrealIRCd backdoor signature
- **verify.sh:** Attempt backdoor command (should fail); verify IRC service is clean

---

### S18 -- UnrealIRCd Authentication Spoofing (CVE-2016-7144)
- **OpenVAS NVT:** UnrealIRCd Authentication Spoofing Vulnerability
- **Port:** 6667/tcp | **CVSS:** 6.8 | **Severity:** Medium
- **CVE:** CVE-2016-7144
- **Vulnerable Version:** UnrealIRCd < 3.2.10.7 / 4.x < 4.0.6
- **Docker Setup:** Install UnrealIRCd 3.2.8.1 (already vulnerable)
- **Remediation:** Upgrade UnrealIRCd to 3.2.10.7+ or 4.0.6+; or remove the service
- **OpenVAS Detection:** Checks version of installed UnrealIRCd
- **verify.sh:** Check UnrealIRCd version is >= 3.2.10.7 or service is removed

---

### S19 -- PHP-CGI Query String Parameter Injection (RCE)
- **OpenVAS NVT:** PHP-CGI-based setups vulnerability when parsing query string parameters
- **Port:** 80/tcp | **CVSS:** 7.5 | **Severity:** High
- **CVE:** CVE-2012-1823, CVE-2012-2311, CVE-2012-2336, CVE-2012-2335
- **Vulnerable Version:** PHP < 5.4.3 / PHP < 5.3.13
- **Docker Setup:** Install Apache with `mod_cgi` and vulnerable PHP-CGI version; the `-s` flag via query string exposes source code, `-d` allows arbitrary config injection
- **Remediation:** Upgrade PHP to 5.4.3+ or 5.3.13+; alternatively, add Apache rewrite rules to block query strings starting with `-`
- **OpenVAS Detection:** Tests `http://target/cgi-bin/php?-s` for source code disclosure
- **verify.sh:** Attempt `?-s` query (should not disclose source); verify PHP applications work

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y apache2 php5-cgi
RUN a2enmod cgi
RUN ln -s /usr/bin/php-cgi /usr/lib/cgi-bin/php
EXPOSE 80
CMD ["apache2ctl", "-D", "FOREGROUND"]
```

---

### S20 -- Samba MS-RPC Remote Shell Command Execution
- **OpenVAS NVT:** Samba MS-RPC Remote Shell Command Execution Vulnerability (Active Check)
- **Port:** 445/tcp | **CVSS:** 6.0 | **Severity:** Medium
- **CVE:** CVE-2007-2447
- **Vulnerable Version:** Samba 3.0.0 to 3.0.25rc3
- **Docker Setup:** Install Samba 3.0.20 (ships with Ubuntu 8.04); the `username map script` parameter allows shell metacharacter injection
- **Remediation:** Upgrade Samba to 3.0.25+; or remove `username map script` from `smb.conf`
- **OpenVAS Detection:** Sends crafted MS-RPC request and checks for command execution
- **verify.sh:** Attempt CVE-2007-2447 exploit (should fail); verify Samba shares are accessible

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y samba
RUN echo '[share]\n  path = /tmp\n  writable = yes\n  guest ok = yes' >> /etc/samba/smb.conf
# Samba 3.0.20 on Hardy is vulnerable to CVE-2007-2447
EXPOSE 139 445
CMD ["smbd", "--foreground", "--no-process-group"]
```

---

### S21 -- OpenSSL CCS Injection (MitM)
- **OpenVAS NVT:** SSL/TLS: OpenSSL CCS Man in the Middle Security Bypass Vulnerability
- **Port:** 5432/tcp | **CVSS:** 6.8 | **Severity:** Medium
- **CVE:** CVE-2014-0224
- **Vulnerable Version:** OpenSSL < 0.9.8za, < 1.0.0m, < 1.0.1h
- **Docker Setup:** Ubuntu 8.04 ships with OpenSSL 0.9.8g which is vulnerable; PostgreSQL with SSL enabled will trigger this
- **Remediation:** Upgrade OpenSSL package to patched version; or if no patched version available for Hardy, disable SSL on internal services and use network-level encryption
- **OpenVAS Detection:** Sends two SSL ChangeCipherSpec requests and checks response
- **verify.sh:** Run `openssl version` and confirm patched; verify PostgreSQL SSL still works

---

### S22 -- Postfix STARTTLS Command Injection
- **OpenVAS NVT:** Multiple Vendors STARTTLS Implementation Plaintext Arbitrary Command Injection
- **Port:** 25/tcp | **CVSS:** 6.8 | **Severity:** Medium
- **CVE:** CVE-2011-0411, CVE-2011-1430, CVE-2011-1431, CVE-2011-1432
- **Vulnerable Version:** Postfix < 2.8.4 / vulnerable STARTTLS implementations
- **Docker Setup:** Install Postfix with SSL/TLS enabled using the old vulnerable version from Ubuntu 8.04 repos
- **Remediation:** Upgrade Postfix to version with STARTTLS fix; or disable STARTTLS if not needed
- **OpenVAS Detection:** Sends crafted STARTTLS request and checks response
- **verify.sh:** Verify Postfix version is patched; verify mail service operates correctly

---

### S23 -- PostgreSQL SSL/TLS Deprecated Protocols (POODLE)
- **OpenVAS NVT:** SSL/TLS: SSLv3 Protocol CBC Cipher Suites Info Disclosure (POODLE)
- **Port:** 5432/tcp | **CVSS:** 4.3 | **Severity:** Medium
- **CVE:** CVE-2014-3566
- **Vulnerable Config:** PostgreSQL compiled against old OpenSSL, supports SSLv3
- **Docker Setup:** Install PostgreSQL with SSL enabled; old OpenSSL supports SSLv3 by default
- **Remediation:** Configure `postgresql.conf` to set `ssl_min_protocol_version = 'TLSv1.2'` (if supported) or upgrade OpenSSL and disable SSLv3 system-wide in `/etc/ssl/openssl.cnf`
- **OpenVAS Detection:** Checks if SSLv3 protocol is accepted by the service
- **verify.sh:** Attempt SSLv3 connection (should fail); verify TLS connection works

---

### S24 -- Postfix SSL/TLS FREAK & LogJam Export Ciphers
- **OpenVAS NVT:** SSL/TLS RSA_EXPORT (FREAK) / DHE_EXPORT (LogJam) Downgrade
- **Port:** 25/tcp | **CVSS:** 4.3 | **Severity:** Medium
- **CVE:** CVE-2015-0204 (FREAK), CVE-2015-4000 (LogJam)
- **Vulnerable Config:** Old OpenSSL accepts `RSA_EXPORT` and `DHE_EXPORT` cipher suites
- **Docker Setup:** Install Postfix with TLS enabled using old OpenSSL that supports export ciphers
- **Remediation:** Upgrade OpenSSL; configure Postfix `smtpd_tls_exclude_ciphers = EXPORT, DES, RC4` in `main.cf`; or set `smtpd_tls_mandatory_ciphers = high`
- **OpenVAS Detection:** Checks if export cipher suites are accepted
- **verify.sh:** Attempt connection with export ciphers (should fail); verify TLS mail delivery works

---

## Category 3: Access Control & Permissions (S25-S29)

### S25 -- Cleartext Transmission of Sensitive Information via HTTP
- **OpenVAS NVT:** Cleartext Transmission of Sensitive Information via HTTP
- **Port:** 80/tcp | **CVSS:** 4.8 | **Severity:** Medium
- **Vulnerable Config:** phpMyAdmin, TikiWiki, and TWiki login forms served over HTTP without HTTPS redirect
- **Docker Setup:** Install Apache + phpMyAdmin without SSL; login form transmits passwords in cleartext
- **Remediation:** Enable `mod_ssl`, generate/install SSL certificate, configure HTTPS redirect for all login pages
- **OpenVAS Detection:** Checks for HTTP forms with password fields not using HTTPS
- **verify.sh:** Verify HTTPS redirect is active for login pages; verify applications still work

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php5 php5 php5-mysql phpmyadmin
RUN echo 'Include /etc/phpmyadmin/apache.conf' >> /etc/apache2/apache2.conf
# No SSL configured - passwords transmitted in cleartext
EXPOSE 80
CMD ["apache2ctl", "-D", "FOREGROUND"]
```

---

### S26 -- Apache httpOnly Cookie Information Disclosure
- **OpenVAS NVT:** Apache HTTP Server 'httpOnly' Cookie Information Disclosure Vulnerability
- **Port:** 80/tcp | **CVSS:** 4.3 | **Severity:** Medium
- **Vulnerable Config:** Apache error responses include `Set-Cookie` headers that leak httpOnly cookie values through `TRACE` method or error pages
- **Docker Setup:** Install Apache 2.2 with default configuration
- **Remediation:** Upgrade Apache or add `Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure` in config; enable `mod_headers`
- **OpenVAS Detection:** Checks if cookies lack httpOnly flag in error responses
- **verify.sh:** Verify cookies have httpOnly flag; verify Apache serves pages

---

### S27 -- SSL/TLS Certificate Expired
- **OpenVAS NVT:** SSL/TLS: Certificate Expired
- **Port:** 25/tcp, 5432/tcp | **CVSS:** 5.0 | **Severity:** Medium
- **Vulnerable Config:** SSL certificates expired on 2010-04-16
- **Docker Setup:** Generate a self-signed SSL certificate with intentionally past expiry date; configure Postfix and PostgreSQL to use it
- **Remediation:** Generate new self-signed certificate with valid expiry: `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes`; update service configs to use new cert
- **OpenVAS Detection:** Checks SSL certificate expiry dates
- **verify.sh:** Connect with `openssl s_client` and verify cert is not expired; verify services work

---

### S28 -- SSL/TLS Weak Signature Algorithm (Certificate)
- **OpenVAS NVT:** SSL/TLS: Certificate Signed Using A Weak Signature Algorithm
- **Port:** 25/tcp, 5432/tcp | **CVSS:** 4.0 | **Severity:** Medium
- **Vulnerable Config:** SSL certificate signed with MD5 or SHA-1
- **Docker Setup:** Generate certificate with SHA-1 signature: `openssl req -x509 -sha1 ...`
- **Remediation:** Regenerate certificate with SHA-256: `openssl req -x509 -sha256 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes`
- **OpenVAS Detection:** Checks certificate signature algorithm
- **verify.sh:** Verify certificate uses SHA-256+; verify SSL services work

---

### S29 -- Distributed Ruby (DRb) No ACL / Unrestricted Access
- **OpenVAS NVT:** Distributed Ruby (dRuby/DRb) Multiple Remote Code Execution Vulnerabilities
- **Port:** 8787/tcp | **CVSS:** 10.0 | **Severity:** High
- **Vulnerable Config:** DRb service running with `$SAFE >= 1` but no ACL restrictions, allowing arbitrary command execution from any host
- **Docker Setup:** Install Ruby, create a DRb service script listening on 0.0.0.0:8787 without ACL
- **Remediation:** Add ACL to DRb service using `drb/acl` library to restrict to trusted hosts; set `$SAFE = 4` or disable the service entirely; alternatively, bind to 127.0.0.1 only
- **OpenVAS Detection:** Sends crafted command to DRb service and checks for execution
- **verify.sh:** Attempt remote DRb command (should fail); verify service is restricted or stopped

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y ruby
# Create vulnerable DRb service
RUN echo 'require "drb/drb"\nclass TimeServer\n  def get_current_time\n    return Time.now\n  end\nend\nDRb.start_service("druby://0.0.0.0:8787", TimeServer.new)\nDRb.thread.join' > /opt/drb_service.rb
EXPOSE 8787
CMD ["ruby", "/opt/drb_service.rb"]
```

---

## Category 4: Network Exposure / Unnecessary Services (S30-S33)

### S30 -- Telnet Service Running (Unencrypted Cleartext Login)
- **OpenVAS NVT:** Telnet Unencrypted Cleartext Login
- **Port:** 23/tcp | **CVSS:** 4.8 | **Severity:** Medium
- **Vulnerable Config:** Telnet daemon is running, all logins transmitted in cleartext
- **Docker Setup:** Install `telnetd` and `xinetd`, enable telnet service
- **Remediation:** Disable telnet service: `update-rc.d -f xinetd remove` or remove `telnetd` package; ensure SSH is available as replacement
- **OpenVAS Detection:** Detects telnet service and reports cleartext login
- **verify.sh:** Verify port 23 is closed or telnet is unresponsive; verify SSH works on port 22

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y telnetd xinetd openssh-server
RUN mkdir -p /var/run/sshd
EXPOSE 22 23
CMD service xinetd start && /usr/sbin/sshd -D
```

---

### S31 -- rlogin Service Running (Passwordless/Unencrypted)
- **OpenVAS NVT:** rlogin Passwordless / Unencrypted Cleartext Login
- **Port:** 513/tcp | **CVSS:** 7.5 | **Severity:** High
- **CVE:** CVE-1999-0651
- **Vulnerable Config:** rlogin service is running; `.rhosts` or `hosts.equiv` may allow passwordless login; all traffic is unencrypted
- **Docker Setup:** Install `rsh-server`, configure `/etc/hosts.equiv` or per-user `.rhosts` for passwordless access
- **Remediation:** Remove `rsh-server` package entirely: `apt-get remove rsh-server`; remove `.rhosts` files; ensure SSH is the only remote access method
- **OpenVAS Detection:** Detects rlogin service and attempts connection
- **verify.sh:** Verify port 513 is closed; verify SSH works

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y rsh-server openssh-server xinetd
RUN echo "+ +" > /etc/hosts.equiv
RUN mkdir -p /var/run/sshd
EXPOSE 22 513
CMD service xinetd start && /usr/sbin/sshd -D
```

---

### S32 -- Ingreslock Backdoor Service
- **OpenVAS NVT:** Possible Backdoor: Ingreslock
- **Port:** 1524/tcp | **CVSS:** 10.0 | **Severity:** High
- **Vulnerable Config:** A root shell is bound to port 1524 (the "Ingreslock" backdoor), answering `id;` with `uid=0(root) gid=0(root)`
- **Docker Setup:** Create a netcat/socat listener on port 1524 that spawns `/bin/sh` as root
- **Remediation:** Kill the backdoor process; remove the backdoor script/binary; block port 1524 with iptables: `iptables -A INPUT -p tcp --dport 1524 -j DROP`
- **OpenVAS Detection:** Connects to port 1524 and sends `id;` command
- **verify.sh:** Verify port 1524 is closed/unreachable; verify no rogue listeners

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y netcat-openbsd openssh-server
RUN mkdir -p /var/run/sshd
# Simulate ingreslock backdoor
RUN echo '#!/bin/bash\nwhile true; do nc -l -p 1524 -e /bin/sh; done' > /opt/backdoor.sh && chmod +x /opt/backdoor.sh
EXPOSE 22 1524
CMD /opt/backdoor.sh & /usr/sbin/sshd -D
```

---

### S33 -- Java RMI Insecure Default Configuration (RCE)
- **OpenVAS NVT:** Java RMI Server Insecure Default Configuration Remote Code Execution
- **Port:** 1099/tcp | **CVSS:** 10.0 | **Severity:** High
- **Vulnerable Config:** Java RMI registry running with class loading enabled from remote HTTP URLs, allowing unauthenticated RCE
- **Docker Setup:** Install Java, create RMI registry service with `java.rmi.server.useCodebaseOnly=false` (or default pre-Java 7u21)
- **Remediation:** Disable remote class loading: set `java.rmi.server.useCodebaseOnly=true`; restrict RMI access with security policy; or disable the RMI service if not needed
- **OpenVAS Detection:** Attempts to load a Java class via remote HTTP URL
- **verify.sh:** Attempt remote class loading (should fail); verify RMI service rejects remote codebases or is stopped

```dockerfile
FROM navig/ubuntu:8.04
RUN apt-get update && apt-get install -y default-jdk
# Create a simple RMI registry with insecure defaults
RUN echo '#!/bin/bash\nrmiregistry 1099 &\nsleep infinity' > /opt/start_rmi.sh && chmod +x /opt/start_rmi.sh
EXPOSE 1099
CMD ["/opt/start_rmi.sh"]
```

---

## Summary Table

| ID | Vulnerability | Port | CVSS | Category | OpenVAS Detectable | Remediation Action |
|---|---|---|---|---|---|---|
| S01 | SSH Weak Encryption Algorithms | 22 | 4.3 | Config | Yes | Edit sshd_config Ciphers |
| S02 | SSH Weak MAC Algorithms | 22 | 2.6 | Config | Yes | Edit sshd_config MACs |
| S03 | SSH Default Credentials | 22 | 7.5 | Config | Yes | Change passwords / disable PasswordAuth |
| S04 | FTP Anonymous Login | 21 | 6.4 | Config | Yes | Edit vsftpd.conf anonymous_enable=NO |
| S05 | FTP Unencrypted Login | 21 | 4.8 | Config | Yes | Enable vsftpd SSL/TLS |
| S06 | MySQL Root Empty Password | 3306 | 9.0 | Config | Yes | Set strong password, bind localhost |
| S07 | PostgreSQL Weak Password | 5432 | 9.0 | Config | Yes | Change password, restrict pg_hba.conf |
| S08 | VNC Weak Password | 5900 | 9.0 | Config | Yes | Change/strengthen VNC password |
| S09 | VNC Unencrypted | 5900 | 4.8 | Config | Yes | Tunnel VNC through SSH or disable |
| S10 | Apache TRACE/TRACK Enabled | 80 | 5.8 | Config | Yes | TraceEnable Off |
| S11 | Apache PUT/DELETE (WebDAV) | 80 | 7.5 | Config | Yes | Disable mod_dav or add auth |
| S12 | Apache /doc Browsable | 80 | 5.0 | Config | Yes | Restrict /doc directory |
| S13 | phpinfo() Exposed | 80 | 7.5 | Config | Yes | Remove phpinfo.php |
| S14 | Postfix VRFY/EXPN | 25 | 5.0 | Config | Yes | disable_vrfy_command=yes |
| S15 | DistCC Unrestricted RCE | 3632 | 9.3 | Config | Yes | Add --allow restriction or stop |
| S16 | vsftpd 2.3.4 Backdoor | 21 | 7.5 | Patch | Yes | Install clean vsftpd |
| S17 | UnrealIRCd Backdoor | 6667 | 7.5 | Patch | Yes | Install verified UnrealIRCd |
| S18 | UnrealIRCd Auth Spoofing | 6667 | 6.8 | Patch | Yes | Upgrade to 3.2.10.7+ |
| S19 | PHP-CGI RCE | 80 | 7.5 | Patch | Yes | Upgrade PHP to 5.4.3+ |
| S20 | Samba MS-RPC RCE | 445 | 6.0 | Patch | Yes | Upgrade Samba / remove username map script |
| S21 | OpenSSL CCS Injection | 5432 | 6.8 | Patch | Yes | Upgrade OpenSSL |
| S22 | Postfix STARTTLS Injection | 25 | 6.8 | Patch | Yes | Upgrade Postfix |
| S23 | PostgreSQL SSLv3 POODLE | 5432 | 4.3 | Patch | Yes | Upgrade OpenSSL / disable SSLv3 |
| S24 | FREAK/LogJam Export Ciphers | 25 | 4.3 | Patch | Yes | Upgrade OpenSSL / exclude export ciphers |
| S25 | HTTP Cleartext Passwords | 80 | 4.8 | Access | Yes | Enable HTTPS redirect |
| S26 | Apache httpOnly Cookie Leak | 80 | 4.3 | Access | Yes | Add HttpOnly;Secure flags |
| S27 | SSL/TLS Certificate Expired | 25,5432 | 5.0 | Access | Yes | Regenerate certificate |
| S28 | SSL/TLS Weak Signature | 25,5432 | 4.0 | Access | Yes | Regenerate with SHA-256 |
| S29 | DRb Unrestricted RCE | 8787 | 10.0 | Access | Yes | Add ACL or bind localhost |
| S30 | Telnet Cleartext Service | 23 | 4.8 | Network | Yes | Disable telnet, use SSH |
| S31 | rlogin Passwordless | 513 | 7.5 | Network | Yes | Remove rsh-server |
| S32 | Ingreslock Backdoor | 1524 | 10.0 | Network | Yes | Kill process, block port |
| S33 | Java RMI Insecure Config | 1099 | 10.0 | Network | Yes | Disable class loading / stop RMI |

---

## Docker Architecture Notes

### Base Image
```
navig/ubuntu:8.04
```
Ubuntu 8.04 (Hardy Heron) -- matches Metasploitable 2's base OS. Package repos may need to point to `old-releases.ubuntu.com`:
```dockerfile
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list
```

### Multi-Service Containers
Some scenarios can be **grouped** into a single container to more faithfully reproduce the Metasploitable 2 attack surface. Suggested groupings:

- **Web Stack Container (S10-S13, S19, S25-S26):** Apache + PHP + phpMyAdmin + phpinfo
- **SSH Container (S01-S03):** OpenSSH with weak config
- **FTP Container (S04-S05, S16):** vsftpd with anon + no TLS + backdoor
- **Database Container (S06-S07, S21, S23, S27-S28):** MySQL + PostgreSQL with weak passwords + bad SSL
- **Mail Container (S14, S22, S24):** Postfix with VRFY + STARTTLS vuln + export ciphers
- **Legacy Services Container (S30-S32):** telnet + rlogin + ingreslock
- **Misc Services Container (S08-S09, S15, S17-S18, S29, S33):** VNC + DistCC + IRC + DRb + RMI

### Verification Strategy
Each `verify.sh` follows the SysRepair-Bench dual-check pattern:
1. **Exploit Check (PoC):** Attempt to reproduce the vulnerability (should FAIL after remediation)
2. **Functionality Check (Regression):** Verify the service still works correctly after remediation

```bash
#!/bin/bash
# Example verify.sh pattern
set -e

# PoC: vulnerability should be gone
if nmap -sV -p 22 --script ssh2-enum-algos localhost | grep -q "arcfour"; then
    echo "FAIL: Weak cipher arcfour still accepted"
    exit 1
fi

# Regression: service should still work
if ! ssh -o BatchMode=yes -o ConnectTimeout=5 testuser@localhost echo "OK" 2>/dev/null; then
    echo "FAIL: SSH service is broken"
    exit 1
fi

echo "PASS: Vulnerability remediated, service operational"
exit 0
```

---

## Excluded Vulnerabilities (Out of Scope)

The following OpenVAS findings from Metasploitable 2 are **NOT included** because they require source code fixes (SWE-bench territory) or are inherent to the platform:

| Vulnerability | Reason Excluded |
|---|---|
| TWiki XSS & Command Execution (CVE-2008-5304/5305) | Application source code bug (eval injection in %SEARCH{}) |
| TWiki CSRF (CVE-2009-1339, CVE-2009-4898) | Application logic bug, requires code patch |
| TWiki XSS (CVE-2018-20212) | Application code bug |
| Tiki Wiki CMS < 4.2 Multiple Vulns (CVE-2010-1133-1136) | SQL injection / auth bypass in app code |
| Tiki Wiki SQL Injection (CVE-2018-20719) | Application code bug in tiki-user_tasks.php |
| Tiki Wiki Input Sanitation (CVE-2008-5318/5319) | Application code bug in tiki-error.php |
| Tiki Wiki fixedURLData LFI (CVE-2016-10143) | Application code bug in display_banner.php |
| awiki Multiple LFI | Application code bug, product is abandoned (WillNotFix) |
| phpMyAdmin error.php XSS | Application code bug |
| OS End of Life Detection | Inherent to Ubuntu 8.04; not remediable without OS migration |
| TCP timestamps | Kernel-level sysctl tuning, negligible security impact |
| SSH Weak MAC Algorithms | Included as S02 (borderline Low but actionable config fix) |
