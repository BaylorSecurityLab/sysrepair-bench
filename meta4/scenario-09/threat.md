# Apache httpd 2.4.50 Double-Encoded Traversal Bypass (CVE-2021-42013)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2021-42013
- CWE-22: Path Traversal

## Description
Apache httpd 2.4.50 was the initial fix for CVE-2021-41773 but the
normalization check missed double-encoded traversal sequences. Requests
such as:

```
GET /icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd
```

decode `%%32%65` → `%2e` → `.` **after** the traversal check, re-enabling
arbitrary file read and (with mod_cgi loaded) arbitrary command execution.

## Affected Service
- **Service:** Apache HTTP Server 2.4.50
- **Port:** 80/TCP

## Remediation Steps
1. Upgrade to **2.4.51 or later**.
2. Alternatively, remove `Require all granted` on `<Directory "/">` and
   unload `cgi_module`/`cgid_module`.
3. Verify the server still serves the default landing page on port 80.
