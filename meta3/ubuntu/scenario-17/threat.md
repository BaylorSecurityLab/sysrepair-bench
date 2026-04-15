# payroll_app.php Source-Locked SQL Injection — mod_security WAF Filter (Compensating Control)

## Severity
**High** (CVSS 8.8) — vulnerability; WAF reduces exploitability to Low

## CVE / CWE
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- No public CVE (application-specific, bespoke PHP)

## Category
Compensating Control — `payroll_app.php` is a third-party binary whose source
cannot be modified. The agent must filter malicious SQL injection payloads at
the Apache/ModSecurity layer while keeping legitimate logins operational.

## Description
`payroll_app.php` constructs MySQL queries by directly interpolating POST
parameters without prepared statements or escaping:

```php
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
```

An attacker can submit a tautology or UNION-based payload in the `username`
field to bypass authentication or dump the database:

- Tautology bypass: `username=admin' OR '1'='1`
- UNION dump: `username=' UNION SELECT 1,2,3,table_name FROM information_schema.tables-- -`

Because the PHP source is locked (binary-distributed, vendor-controlled, or
policy-protected), the SQLi cannot be patched in code. The compensating control
is an Apache ModSecurity rule set targeting the POST body of requests to
`/payroll_app.php` and blocking known SQLi payload patterns.

## Affected Service
- **Service:** Apache2 + payroll_app.php
- **Port:** 80/TCP
- **Path:** `/payroll_app.php`

## Constraint
`payroll_app.php` must remain running and must accept legitimate username/password
combinations. The compensating control must not disable or replace the application.

## Remediation Steps
1. Install ModSecurity and enable it:
   ```bash
   apt-get install -y libapache2-mod-security2
   a2enmod security2
   cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
   sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
   ```

2. Create a custom rule file scoped to the payroll application:
   ```bash
   cat > /etc/modsecurity/payroll_sqli.conf <<'EOF'
   # Block tautology-based SQLi patterns on payroll login
   SecRule REQUEST_URI "@rx /payroll_app\.php" \
     "id:9010,phase:2,chain,deny,status:403,log,msg:'payroll_app SQLi tautology'"
     SecRule ARGS:username "@rx (?i)(\bOR\b|\bAND\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+" ""

   # Block UNION SELECT injection
   SecRule REQUEST_URI "@rx /payroll_app\.php" \
     "id:9011,phase:2,chain,deny,status:403,log,msg:'payroll_app SQLi UNION SELECT'"
     SecRule ARGS "@rx (?i)UNION\s+(ALL\s+)?SELECT" ""

   # Block SQL comment sequences used to truncate query
   SecRule REQUEST_URI "@rx /payroll_app\.php" \
     "id:9012,phase:2,chain,deny,status:403,log,msg:'payroll_app SQLi comment terminator'"
     SecRule ARGS "@rx (--|#|/\*)" ""
   EOF
   ```

3. Include the rule file:
   ```bash
   echo 'Include /etc/modsecurity/payroll_sqli.conf' \
     >> /etc/modsecurity/modsecurity.conf
   ```

4. Reload Apache:
   ```bash
   service apache2 reload
   ```

5. Verify that the tautology payload returns 403 and a valid login returns 200.

## Build

Build from the `meta3/ubuntu/` directory (one level above this scenario):

```
docker build -f scenario-17/Dockerfile -t meta3u-s17 .
docker run -d --name meta3u-s17 -p 8080:80 meta3u-s17
docker exec meta3u-s17 /bin/bash /verify.sh
docker stop meta3u-s17 && docker rm meta3u-s17
```
