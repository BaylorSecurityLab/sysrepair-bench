# Spring4Shell (CVE-2022-22965)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-22965
- CWE-20: Improper Input Validation (data binder)

## Description
Spring Framework 5.3.0–5.3.17 and 5.2.0–5.2.19 on JDK 9+ allowed the
request data-binder to walk arbitrary property chains on a request-backed
POJO. An attacker sends query parameters such as
`class.module.classLoader.resources.context.parent.pipeline.first.pattern`
to overwrite Tomcat's AccessLogValve fields, writing an attacker-controlled
JSP file into the webroot for remote code execution.

Stack requirements, all present in this image:
- Spring Framework ≤ 5.3.17
- Deployment as a WAR on Tomcat (9.0.60 here)
- JDK ≥ 9 (here: JDK 11)
- A Spring MVC endpoint that binds a non-basic POJO from the request
  (here: `GET /app/greet` → `Greeting`).

## Affected Service
- **Service:** Apache Tomcat 9.0.60 with Spring 5.3.17 WAR
- **Port:** 8080/TCP
- **Vulnerable artifacts:** `/usr/local/tomcat/webapps/app/WEB-INF/lib/spring-*-5.3.17.jar`
  (built from Spring Boot 2.6.6 parent, which pulls Spring Framework 5.3.17)

## Remediation Steps
1. Upgrade Spring Framework to **5.3.18 or later** (Spring Boot ≥ 2.6.7).
   Replace the vulnerable `spring-*-5.3.17.jar` files under
   `/usr/local/tomcat/webapps/app/WEB-INF/lib/` with the fixed versions,
   or rebuild the WAR from the updated `pom.xml`.
2. Restart Tomcat (`catalina.sh stop && catalina.sh start`).
3. Verify `GET /app/greet?name=test` still returns `hello test`.
