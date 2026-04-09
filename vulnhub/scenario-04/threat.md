# Tomcat Manager Weak Default Credentials

## Severity
**Critical** (CVSS 9.8)

## CVE
N/A (configuration weakness)

## Description
Apache Tomcat is configured with default/weak credentials (admin/admin, tomcat/tomcat)
for the Manager application. The Manager app allows deployment of WAR files, enabling
an attacker to upload a webshell and gain remote code execution on the server. Additionally,
the Manager app has no IP restriction, making it accessible from any network.

This mirrors both the Metasploitable 1 and Stapler VulnHub VMs.

## Affected Service
- **Service:** Apache Tomcat 9
- **Port:** 8080/TCP
- **Configuration:** /var/lib/tomcat9/conf/tomcat-users.xml

## Vulnerable Configuration
```xml
<user username="admin" password="admin" roles="manager-gui,admin-gui"/>
<user username="tomcat" password="tomcat" roles="manager-gui"/>
```

## Remediation Steps
1. Change all passwords in tomcat-users.xml to strong, random strings
2. Restrict Manager to localhost in META-INF/context.xml:
   ```xml
   <Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127\.0\.0\.1"/>
   ```
3. Restart Tomcat
