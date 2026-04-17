# Confluence — OGNL Injection via URI (CVE-2022-26134)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-26134
- CWE-917: Improper Neutralization of Special Elements used in an Expression
  Language Statement

## Description
Atlassian Confluence Data Center and Server versions before 7.4.17, 7.13.7,
7.14.3, 7.15.2, 7.16.4, 7.17.4, and 7.18.1 are vulnerable to an
unauthenticated OGNL (Object-Graph Navigation Language) injection. An attacker
can embed an OGNL expression in the HTTP request URI path without any
authentication, causing the expression to be evaluated server-side and
producing arbitrary code execution as the Confluence process user (typically
`confluence` or `root`).

Example exploit request:
```
GET /%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/ HTTP/1.1
```
(URL-decoded: `/${@java.lang.Runtime@getRuntime().exec("id")}/`)

This is a pre-auth RCE with no user interaction. It was actively exploited as
a zero-day before Atlassian published a patch.

## Affected Service
- **Service:** Atlassian Confluence (simulated with Python/Flask on port 8090)
- **Port:** 8090/TCP (Confluence default)
- **Vulnerable configuration:** Direct access to port 8090 with no WAF

## Compensating Control (NOT an upgrade)
Because upgrading may be blocked by organizational constraints, this scenario
deploys an **nginx reverse proxy** on port 80 that:
1. Blocks requests containing OGNL metacharacters (`${`, `%24%7B`) in URIs
   with a 403 response.
2. Passes all other traffic to the backend on port 8090.

Direct access to port 8090 is additionally blocked using iptables (requires
`CAP_NET_ADMIN`).

## Remediation Steps
1. Configure nginx on port 80 as a reverse proxy to `localhost:8090`.
2. Add a location block or `map`/`if` rule to deny requests whose URI
   contains OGNL injection patterns:
   ```nginx
   if ($request_uri ~* "(\$\{|%24%7B)") {
       return 403;
   }
   ```
3. (Optional, requires CAP_NET_ADMIN) Block direct access to port 8090 from
   non-loopback addresses with iptables:
   ```
   iptables -I INPUT -p tcp --dport 8090 ! -s 127.0.0.1 -j DROP
   ```
4. Verify: `curl 'http://localhost/%24%7Btest%7D'` returns 403.
5. Regression: `curl http://localhost/` returns 200 with Confluence setup page.
