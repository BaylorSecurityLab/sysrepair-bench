# Apache Tomcat Partial-PUT Deserialization RCE (CVE-2025-24813)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2025-24813
- CWE-502: Deserialization of Untrusted Data

## Description
Tomcat 9.0.0–9.0.98 (and corresponding 10.1.x / 11.0.x ranges) support
partial PUT uploads. When `readonly=false` is set on the default servlet
AND the application uses the `PersistentManager` + `FileStore` session
store, an attacker can:

1. Upload a serialized Java payload via a partial PUT, placed at the path
   Tomcat will later treat as a session file.
2. Send a subsequent request with a forged `JSESSIONID` cookie that matches
   the uploaded file name.
3. The PersistentManager deserializes the attacker-controlled file on
   session load, executing the gadget chain with Tomcat's privileges.

## Affected Service
- **Service:** Apache Tomcat 9.0.98
- **Port:** 8080/TCP
- **Vulnerable configuration:**
  - `/usr/local/tomcat/conf/web.xml` default servlet `readonly=false`
  - `/usr/local/tomcat/conf/Catalina/localhost/ROOT.xml` with
    `PersistentManager` + `FileStore`

## Remediation Steps
Any one of the following closes the vulnerability; the most minimal fix is
preferred:

1. **Config** (preferred): flip the default servlet back to
   `readonly=true` in `/usr/local/tomcat/conf/web.xml`.
2. **Config**: remove the `PersistentManager` / `FileStore` block from
   `ROOT.xml` (fall back to the in-memory session manager).
3. **Patch**: upgrade to Tomcat **9.0.99 / 10.1.35 / 11.0.3** or later.

After remediation, restart Tomcat and verify that the default landing page
still responds on 8080.
