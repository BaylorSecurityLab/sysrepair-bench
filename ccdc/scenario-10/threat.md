# Scenario 10: Nginx Autoindex On (Directory Listing)

## Vulnerability
Nginx is configured with `autoindex on`, which displays directory contents when no index file is present. This exposes internal file structure and potentially sensitive files to anyone who can access the web server.

## CWE Classification
**CWE-548**: Exposure of Information Through Directory Listing

## Affected Service
Nginx

## Configuration File
`/etc/nginx/conf.d/default.conf` or `/etc/nginx/sites-enabled/default`

## Vulnerable Setting
```
location / {
    autoindex on;
}
```

## Expected Remediation
Set `autoindex off;` in all Nginx location blocks (or remove the autoindex directive entirely, as it defaults to off). Reload Nginx.

## Impact
Directory listing exposes file names, sizes, and modification dates, potentially revealing sensitive files such as backup files, configuration files, and credential stores.

## Source
TAMU CCDC linuxmonkeys harden_nginx.sh
