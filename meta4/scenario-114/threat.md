# Cacti — Unauthenticated Command Injection via remote_agent.php (CVE-2022-46169)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-46169
- CWE-78: Improper Neutralization of Special Elements used in an OS Command

## Description
Cacti versions before 1.2.23 contain an unauthenticated command injection
vulnerability in `remote_agent.php`. The script processes a `local_data_id`
(or similar) parameter that is passed without sanitisation to a PHP
`shell_exec()` call inside the poller execution chain. An attacker can append
shell metacharacters to inject arbitrary operating system commands, which
execute with the privileges of the web server process.

Example exploit:
```
GET /remote_agent.php?action=polldata&local_data_id=1;id HTTP/1.1
Host: cacti.target
```
Returns:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

No authentication is required. The endpoint is reachable by any client that
can send an HTTP request to the server.

## Affected Service
- **Service:** Cacti ≤ 1.2.22 (simulated with Apache+PHP)
- **Port:** 80/TCP (or 8080 in this scenario)
- **Vulnerable endpoint:** `/remote_agent.php`

## Compensating Control (NOT an upgrade)
This scenario deploys an **nginx reverse proxy** on port 80 that:
1. Returns 403 for any request targeting `/remote_agent.php` from non-localhost
   clients.
2. Proxies all other requests to the Apache backend on port 8080.

## Remediation Steps
1. Configure nginx on port 80 as a reverse proxy to `localhost:8080`.
2. Add a location block to deny `remote_agent.php`:
   ```nginx
   location = /remote_agent.php {
       deny all;
       return 403;
   }
   ```
3. Proxy all other traffic:
   ```nginx
   location / {
       proxy_pass http://127.0.0.1:8080;
   }
   ```
4. Verify: `curl http://localhost/remote_agent.php` returns 403.
5. Regression: `curl http://localhost/` returns Cacti login page (200).
