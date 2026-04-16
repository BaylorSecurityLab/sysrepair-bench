# Log4j 2.15.0 Thread Context Map Bypass (CVE-2021-45046)

## Severity
**Critical** (CVSS 9.0)

## CVE / CWE
- CVE-2021-45046
- CWE-917: Expression Language Injection

## Description
Log4j 2.15.0 was the initial fix for CVE-2021-44228 but its mitigation was
incomplete. When a logging configuration uses a non-default PatternLayout
that references the Thread Context Map (for example `${ctx:userId}`) or a
Thread Context Stack pattern, attacker-controlled values placed into the
context can still include `${jndi:ldap://...}` expressions and trigger
remote code execution in vulnerable JNDI environments, or cause information
disclosure.

The bundled application logs a ThreadContext key `q` populated from the HTTP
query string and its `log4j2.xml` uses a PatternLayout that expands
`${ctx:q}` at layout time — exactly the affected shape.

## Affected Service
- **Port:** 8080/TCP
- **Vulnerable artifact:** `/opt/app/log4j-core-2.15.0.jar`

## Remediation Steps
1. Replace `log4j-core-2.15.0.jar` and `log4j-api-2.15.0.jar` with
   **2.17.1 or later**. (2.16 is vulnerable to CVE-2021-45105; 2.17.0 is
   vulnerable to CVE-2021-44832 — see scenarios 03 and 04.)
2. Additionally, remove the `${ctx:q}` reference from any PatternLayout and
   remove JndiLookup.class from the classpath if upgrade is not immediately
   possible.
3. Verify the HTTP server still responds with `200 ok` on
   `http://127.0.0.1:8080/`.
