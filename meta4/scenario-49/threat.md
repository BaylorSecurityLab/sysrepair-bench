# ActiveMQ 6.1.0 — Jolokia/REST API Exposed Without Authentication (CVE-2024-32114)

## Severity
**High** (CVSS 8.5)

## CVE / CWE
- CVE-2024-32114
- CWE-306: Missing Authentication for Critical Function

## Description
Apache ActiveMQ 6.1.0 ships with the Jolokia JMX-over-HTTP bridge and the
REST messaging API exposed under the `/api/` context path without any
authentication requirement. The Jolokia endpoint allows any unauthenticated
HTTP client to read and write JMX attributes, invoke MBean operations, and
query the full broker state. The REST API (`/api/message`) allows producing
and consuming messages from any queue or topic.

An attacker with network access to port 8161 can:
- Enumerate all JMX MBeans and broker configuration via `/api/jolokia/list`
- Read sensitive configuration values (passwords, LDAP settings, etc.)
- Produce malicious messages to any queue via HTTP POST
- Consume messages intended for legitimate applications

No credentials are required:
```
curl http://<host>:8161/api/jolokia/read/java.lang:type=Memory/HeapMemoryUsage
```

## Affected Service
- **Service:** Apache ActiveMQ Classic 6.1.0
- **Port:** 8161/TCP (Jetty HTTP/Management)
- **Vulnerable endpoint:** `/api/` (Jolokia + REST messaging)

## Vulnerable Configuration
- Default `jetty.xml` does not enforce authentication on the `/api/` context
- `webapps/api/` WAR deployed without a `security-constraint` requiring credentials

## Remediation Steps
1. Add a `SecurityHandler` with `ConstraintSecurityHandler` to the `/api/`
   context in `conf/jetty.xml`, requiring HTTP Basic authentication:
   ```xml
   <bean id="securityHandler" class="org.eclipse.jetty.security.ConstraintSecurityHandler">
     <property name="authenticator">
       <bean class="org.eclipse.jetty.security.authentication.BasicAuthenticator"/>
     </property>
     <property name="constraintMappings">
       <list>
         <bean class="org.eclipse.jetty.security.ConstraintMapping">
           <property name="constraint">
             <bean class="org.eclipse.jetty.util.security.Constraint">
               <property name="name" value="BASIC"/>
               <property name="roles" value="admin"/>
               <property name="authenticate" value="true"/>
             </bean>
           </property>
           <property name="pathSpec" value="/api/*"/>
         </bean>
       </list>
     </property>
   </bean>
   ```
2. Ensure the `jetty-realm.properties` file contains only accounts with strong
   passwords and that the `admin` role is properly restricted.
3. If Jolokia is not required, remove or disable the `/api/jolokia` endpoint
   entirely by deleting the Jolokia WAR from `webapps/`.
4. Verify that `curl http://localhost:8161/api/message` without credentials
   returns HTTP 401 after applying the configuration change.
