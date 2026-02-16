# Cleartext Transmission of Sensitive Information via HTTP

## Severity
**Medium** (CVSS 4.8)

## CVE
CWE-319 (Cleartext Transmission of Sensitive Information)

## Description
The Apache web server on this system serves login forms and phpMyAdmin over unencrypted
HTTP. Sensitive information such as usernames, passwords, session tokens, and database
queries are transmitted in cleartext across the network. An attacker on the same network
segment can passively sniff traffic to capture credentials and session cookies, or perform
active man-in-the-middle attacks to inject malicious content.

phpMyAdmin provides direct database administration access, and its login form is also served
over HTTP, meaning database credentials are exposed in transit.

## Affected Service
- **Service:** Apache HTTP Server 2.2 with PHP5 and phpMyAdmin
- **Port:** 80/TCP
- **Binary:** /usr/sbin/apache2
- **Configuration:** /etc/apache2/sites-available/default

## Vulnerable Configuration
Apache is configured with only HTTP (port 80) enabled. There is no SSL/TLS configuration:

```
# /etc/apache2/sites-available/default
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www
    # No HTTPS redirect, no SSL configuration
</VirtualHost>
```

The `ssl` module is not enabled, and no certificates are installed. All traffic including
login forms and phpMyAdmin sessions are served in cleartext.

## Remediation Steps
1. Enable the Apache SSL module:
   ```
   a2enmod ssl
   ```
2. Generate a self-signed SSL certificate (or install a proper one):
   ```
   openssl req -x509 -newkey rsa:2048 -keyout /etc/ssl/private/server.key \
       -out /etc/ssl/certs/server.crt -days 365 -nodes \
       -subj "/CN=localhost"
   ```
3. Create or enable an SSL virtual host in `/etc/apache2/sites-available/default-ssl`:
   ```
   <VirtualHost *:443>
       ServerAdmin webmaster@localhost
       DocumentRoot /var/www
       SSLEngine on
       SSLCertificateFile /etc/ssl/certs/server.crt
       SSLCertificateKeyFile /etc/ssl/private/server.key
   </VirtualHost>
   ```
4. Enable the SSL site:
   ```
   a2ensite default-ssl
   ```
5. Add an HTTP-to-HTTPS redirect for login pages in the port-80 virtual host:
   ```
   <VirtualHost *:80>
       RewriteEngine On
       RewriteRule ^/login(.*) https://%{HTTP_HOST}/login$1 [R=301,L]
       RewriteRule ^/phpmyadmin(.*) https://%{HTTP_HOST}/phpmyadmin$1 [R=301,L]
   </VirtualHost>
   ```
6. Enable mod_rewrite and restart Apache:
   ```
   a2enmod rewrite
   apache2ctl restart
   ```
