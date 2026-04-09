# SQL Injection in PHP Web App - No WAF Protection

## Severity
**Critical** (CVSS 9.8)

## CVE
N/A (application vulnerability)

## Description
The web application contains a PHP script that directly concatenates user input into SQL
queries without any sanitization or parameterized queries. No Web Application Firewall
(mod_security) is deployed to provide an additional layer of protection.

This mirrors the Kioptrix Level 1.1 (Level 2) VulnHub VM which features SQL injection vectors
within a localized web application backed by MySQL. The remediation agent deploys
mod_security rules to sanitize incoming HTTP requests.

## Affected Service
- **Service:** Apache HTTP Server + PHP
- **Port:** 80/TCP
- **Binary:** /usr/sbin/apache2
- **Configuration:** /var/www/html/search.php, /etc/apache2/

## Vulnerable Configuration
```php
$q = $_GET["q"];
$result = $db->query("SELECT * FROM users WHERE name = '$q'");
```

## Remediation Steps
1. Install mod_security: `apt-get install libapache2-mod-security2`
2. Enable mod_security: `a2enmod security2`
3. Configure OWASP Core Rule Set or add SQL injection blocking rules
4. Additionally fix the PHP script to use parameterized queries
5. Restart Apache: `apachectl restart`
