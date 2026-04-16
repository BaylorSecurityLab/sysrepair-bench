# Apache httpd 2.4.49 Path Traversal → RCE (CVE-2021-41773)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2021-41773
- CWE-22: Path Traversal
- CWE-78: OS Command Injection (via CGI)

## Description
Apache HTTP Server 2.4.49 introduced a URL normalization regression where
`.%2e/` sequences are decoded after the traversal check. Requests such as:

```
GET /icons/.%2e/.%2e/.%2e/.%2e/etc/passwd
```

escape aliased or `Require all granted` directories and read arbitrary
files. If `mod_cgi`/`mod_cgid` is enabled, the same traversal into
`/bin/sh` with a POST body yields arbitrary command execution.

## Affected Service
- **Service:** Apache HTTP Server 2.4.49
- **Port:** 80/TCP
- **Vulnerable binary:** `/usr/local/apache2/bin/httpd`
- **Aggravating config:** mod_cgi/mod_cgid loaded, `Require all granted`
  on `<Directory "/">`

## Remediation Steps
1. Upgrade httpd to **2.4.51 or later** (2.4.50 is also vulnerable — see
   scenario 09).
2. As a temporary compensating control, remove the `Require all granted`
   block on `<Directory "/">` and unload `cgi_module`/`cgid_module`.
3. Verify the server still serves the default landing page on port 80.
