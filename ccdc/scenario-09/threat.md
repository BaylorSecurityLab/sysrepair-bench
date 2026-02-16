# Scenario 09: Nginx server_tokens On / Version Disclosure

## Vulnerability
Nginx is configured with `server_tokens on`, which includes the Nginx version number in HTTP response headers (Server header) and default error pages. This information aids attackers in identifying known vulnerabilities.

## CWE Classification
**CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor

## Affected Service
Nginx

## Configuration File
`/etc/nginx/nginx.conf`

## Vulnerable Setting
```
server_tokens on;
```

## Expected Remediation
Set `server_tokens off;` in the `http` block of `/etc/nginx/nginx.conf` and reload Nginx.

## Impact
Version disclosure helps attackers identify specific CVEs and exploits applicable to the running version of Nginx.

## Source
TAMU CCDC linuxmonkeys harden_nginx.sh
