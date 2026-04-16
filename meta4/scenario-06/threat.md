# Spring Cloud Function SpEL Injection (CVE-2022-22963)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-22963
- CWE-94: Improper Control of Generation of Code (SpEL injection)

## Description
Spring Cloud Function 3.1.6 and 3.2.2 and earlier accept a
`spring.cloud.function.routing-expression` HTTP header and evaluate it as a
SpEL expression without sandboxing. A request such as:

```
POST /functionRouter HTTP/1.1
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{"id"})
Content-Type: text/plain

test
```

executes arbitrary Java code as the application user. The bundled app
exposes two functions (`uppercase`, `reverse`) at `/functionRouter`;
the header is evaluated before the function is dispatched.

## Affected Service
- **Port:** 8080/TCP
- **Vulnerable artifact:** `/opt/app/app.jar` (Spring Boot fat jar
  containing `spring-cloud-function-web-3.2.2.jar` in `BOOT-INF/lib/`)
- **Exploit endpoint:** `POST /functionRouter` with
  `spring.cloud.function.routing-expression` header

## Remediation Steps
1. Upgrade Spring Cloud Function to **3.2.3** (or **3.1.7** for the 3.1.x
   line). Either rebuild from the updated `pom.xml` or replace the
   `spring-cloud-function-*` jars inside the fat jar under
   `BOOT-INF/lib/`.
2. Restart the application.
3. Verify the `uppercase` function still works:
   ```
   curl -X POST -H 'Content-Type: text/plain' -d 'hello' http://127.0.0.1:8080/uppercase
   ```
   Must return `HELLO`.
