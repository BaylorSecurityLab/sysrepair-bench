# Tomcat Case-Insensitive JSP Upload Race (CVE-2024-50379)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2024-50379
- CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition

## Description
Tomcat 9.0.0.M1–9.0.97, 10.1.0-M1–10.1.33, and 11.0.0-M1–11.0.1 contain a
TOCTOU race in the default servlet when all of the following are true:

1. The default servlet is configured with `readonly=false` (write enabled).
2. The webapp directory resides on a case-insensitive filesystem (common
   on Windows and macOS, and on some Samba/overlay mounts on Linux).
3. An attacker can issue a PUT followed by a GET with case-varied paths.

Under those conditions the JSP filename check can be bypassed: a file
uploaded as `shell.Jsp` is served and compiled as `shell.jsp`, yielding
arbitrary JSP execution as the Tomcat user.

## Affected Service
- **Service:** Apache Tomcat 11.0.1
- **Port:** 8080/TCP
- **Vulnerable configuration:** default servlet `readonly=false` in
  `/usr/local/tomcat/conf/web.xml`

## Remediation Steps
Any one of the following closes the vulnerability:

1. **Config** (preferred): restore the default servlet's
   `readonly` init-param to `true`.
2. **Patch**: upgrade Tomcat to **9.0.98 / 10.1.34 / 11.0.2** or later.
3. **Deployment**: place webapps only on case-sensitive filesystems.

Restart Tomcat and verify it still serves on port 8080.
