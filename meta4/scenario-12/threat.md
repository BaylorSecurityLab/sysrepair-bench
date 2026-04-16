# Confluence OGNL Injection RCE (CVE-2022-26134)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-26134
- CWE-917: Expression Language Injection

## Description
Atlassian Confluence Server and Data Center versions prior to 7.18.1
(and a long list of earlier 7.x, 6.x branches) evaluate OGNL expressions
embedded in the URL path through the Velocity template engine. An
unauthenticated request such as:

```
GET /${@java.lang.Runtime@getRuntime().exec("id")}/ HTTP/1.1
```

(URL-encoded) executes arbitrary shell commands as the Confluence JVM
user. Patched versions reject the OGNL expression early in URL routing.

## Affected Service
- **Service:** Confluence Server 7.18.0
- **Port:** 8090/TCP

## Remediation Steps
1. Upgrade to **7.18.1**, **7.4.17**, or any later fixed release. In
   the vendor image this means swapping the container tag, e.g.
   `atlassian/confluence-server:7.18.1`.
2. Compensating control (if immediate upgrade is blocked): put a WAF
   rule in front of Confluence rejecting URL paths containing `${` or
   `%24%7B`.
3. Regression: Confluence UI must still load on port 8090.
