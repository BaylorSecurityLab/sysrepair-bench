# Apache 2.4.49 — Path Traversal + RCE via mod_cgi (CVE-2021-41773)

## Severity
**High** (CVSS 7.5; RCE variant CVSS 9.8)

## CVE / CWE
- CVE-2021-41773
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory

## Description
Apache HTTP Server 2.4.49 introduced a flaw in path normalization that allowed
an attacker to use percent-encoded dot sequences (`%2e`) to escape the document
root and traverse to arbitrary filesystem locations. When `mod_cgi` (or
`mod_cgid`) is also enabled and the target directory has `Options ExecCGI`,
the traversal escalates to unauthenticated remote code execution.

A simple HTTP request such as:
```
GET /cgi-bin/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
```
returns the contents of `/etc/passwd`. When combined with a POST to a cgi-bin
traversal path, an attacker can execute arbitrary shell commands.

This vulnerability was actively exploited within hours of public disclosure.

## Affected Service
- **Service:** Apache HTTP Server 2.4.49 only (fixed in 2.4.51)
- **Port:** 80/TCP
- **Conditions:** `Require all granted` on the root directory AND mod_cgi
  enabled

## Compensating Control (NOT an upgrade)
Because upgrading may not always be possible (locked vendor environment,
certification constraints), this scenario deploys **ModSecurity** as a WAF
with the OWASP Core Rule Set (CRS) to block the encoded traversal sequences
at the HTTP layer. Apache remains at version 2.4.49.

## Remediation Steps
1. Install `libapache2-mod-security2` (Debian/Ubuntu) or `mod_security` (RHEL).
2. Enable ModSecurity with `SecRuleEngine On`.
3. Deploy the OWASP CRS rules (at minimum, rules covering path traversal —
   REQUEST-930-APPLICATION-ATTACK-LFI.conf).
4. Add a custom rule to block `%2e` encoded dot sequences in the URI:
   ```
   SecRule REQUEST_URI "@contains %2e%2e" \
       "id:9000001,phase:1,deny,status:403,msg:'Encoded traversal blocked'"
   ```
5. Verify: `curl -s http://localhost/cgi-bin/%2e%2e/%2e%2e/etc/passwd`
   returns **403**, not file content.
6. Verify Apache version is still 2.4.49: `httpd -v`.
7. Regression: `curl http://localhost/` returns the site HTML.
