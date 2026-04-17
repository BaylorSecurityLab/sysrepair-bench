# WebLogic Console Unauthorized Access via URL Encoding Bypass (CVE-2020-14882)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2020-14882
- CWE-284: Improper Access Control

## Description
Oracle WebLogic Server's administration console is normally protected by
authentication. CVE-2020-14882 is a path traversal / URL encoding bypass that
allows an unauthenticated attacker to access the console by crafting a URL
with double-URL-encoded path separators:

```
GET /console/css/%252e%252e%252fconsole.portal HTTP/1.1
```

When WebLogic processes this URL it decodes `%252e` → `%2e` → `.` so the
effective path becomes `/console/css/../console.portal` — which points at the
console application. Because the authentication check examines the raw
(un-normalised) path, it sees `/console/css/...` and allows the request
without requiring login.

Combined with CVE-2020-14883 (post-auth RCE gadget), this yields an
unauthenticated Remote Code Execution chain against the full WebLogic stack.

## Affected Service
- **Service:** Oracle WebLogic Server admin console (simulated)
- **Port:** 7001/TCP (WebLogic default admin port)
- **Vulnerable versions:** WebLogic 10.3.6.0, 12.1.3.0, 12.2.1.3, 12.2.1.4, 14.1.1.0

## Vulnerable Configuration
The console is reachable on port 7001 with no upstream proxy normalising or
blocking encoded traversal paths.

## Remediation (Compensating Control)
Deploy an nginx reverse proxy that blocks access to `/console` paths entirely
from non-admin sources, and normalises URL encoding before forwarding:

```nginx
# Block the console path including URL-encoded traversal attempts
location ~* /console {
    deny all;
    return 403;
}

location / {
    proxy_pass http://127.0.0.1:7001;
}
```

This stops the URL-encoding bypass because nginx processes the path before
the request reaches WebLogic. An attacker sending the double-encoded URL hits
nginx's `/console` deny rule regardless of encoding tricks.

Additionally, restrict port 7001 to trusted admin IPs using iptables so the
WebLogic port is not directly reachable from the internet.
