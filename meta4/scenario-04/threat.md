# Log4j 2.17.0 JDBC Appender RCE (CVE-2021-44832)

## Severity
**Medium** (CVSS 6.6)

## CVE / CWE
- CVE-2021-44832
- CWE-20: Improper Input Validation (JNDI DataSource)

## Description
Log4j 2.17.0 retained a JDBC Appender that fetched its JDBC DataSource via
an arbitrary JNDI name from the log4j configuration. An attacker able to
modify the logging configuration (for example through a writable config
volume, environment override, or deserialization chain) can point the JNDI
name at a remote LDAP server and cause Log4j to load a remote Java class,
yielding remote code execution.

## Affected Service
- **Port:** 8080/TCP
- **Vulnerable artifact:** `/opt/app/log4j-core-2.17.0.jar`
- **Vulnerable configuration:** `log4j2.xml` JDBC Appender with
  `DataSource jndiName="..."`

## Remediation Steps
1. Upgrade `log4j-core`/`log4j-api` to **2.17.1 or later** (Java 8) or
   **2.12.4** (Java 7) or **2.3.2** (Java 6).
2. Remove the `<JDBC>` appender or pin its `DataSource jndiName` to a local,
   non-remote resource.
3. Confirm the HTTP server still serves on 8080.
