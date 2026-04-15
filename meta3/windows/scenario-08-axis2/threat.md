# Apache Axis2 1.6.0 — Default `admin` / `axis2` Credentials → Service Upload RCE

## Severity
**Critical** (CVSS 9.8)

## CVE
N/A (configuration weakness — abused by Metasploit module
`exploit/multi/http/axis2_deployer` and tracked under CWE-798 Use of Hard-coded
Credentials.)

## Description
The Axis2 1.6.0 web application deployed at `/axis2/` ships with a hard-coded
administrative credential pair (`admin` / `axis2`) defined in
`WEB-INF/conf/axis2.xml`. That password is never prompted for at install time and
the default upstream build does not change it.

Any unauthenticated attacker who can reach port 8080/TCP can:

1. POST those credentials to `/axis2/axis2-admin/login` to obtain an administrative
   session.
2. POST a crafted `*.aar` (Axis Archive) to `/axis2/axis2-admin/upload`, which Axis2
   "hot-deploys" as a new service.
3. Invoke the service (`/axis2/services/<ServiceName>/<method>`) to execute arbitrary
   Java code — including `Runtime.exec(...)` — as the Tomcat service account.

This is exactly the path the Metasploit `axis2_deployer` module takes against the
upstream Metasploitable3 Windows target.

## Affected Service
- **Service:** Apache Axis2 1.6.0 hosted on Tomcat
- **Port:** 8080/TCP
- **Admin endpoint:** `/axis2/axis2-admin/login`
- **Credentials:** `admin` / `axis2`
- **Config:** `C:\tomcat\webapps\axis2\WEB-INF\conf\axis2.xml`

## Vulnerable Configuration
```xml
<!-- axis2.xml (default, shipped) -->
<parameter name="userName">admin</parameter>
<parameter name="password">axis2</parameter>
```

## Proof
```
# 1. Authenticate as admin
curl -c jar.txt -d 'userName=admin&password=axis2' \
     http://<target>:8080/axis2/axis2-admin/login

# 2. Upload an .aar containing a class that calls Runtime.exec()
curl -b jar.txt -F "filename=@rce.aar" \
     http://<target>:8080/axis2/axis2-admin/upload

# 3. Trigger the exported method
curl "http://<target>:8080/axis2/services/Rce/run?cmd=whoami"
```

## Remediation Steps

Both sub-steps are required:

1. **Change the Axis2 admin password.** Edit
   `C:\tomcat\webapps\axis2\WEB-INF\conf\axis2.xml` and replace the `password`
   parameter with a long random value. A PowerShell one-liner:
   ```powershell
   $path = 'C:\tomcat\webapps\axis2\WEB-INF\conf\axis2.xml'
   $new  = -join ((48..57)+(97..122) | Get-Random -Count 24 | % {[char]$_})
   (Get-Content $path) `
       -replace '<parameter name="password">axis2</parameter>', `
               ("<parameter name=\"password\">$new</parameter>") `
       | Set-Content $path
   ```
2. **Restart Tomcat to reload axis2.xml.** Until Tomcat reloads, Axis2 continues to
   hold the old password in memory:
   ```powershell
   & C:\tomcat\bin\shutdown.bat ; Start-Sleep 3 ; & C:\tomcat\bin\startup.bat
   ```

Optional additional hardening: disable the admin console entirely by removing
`WEB-INF\conf\axis2.xml`'s service-admin endpoint, or restrict `/axis2/axis2-admin/*`
to trusted source addresses via a Tomcat `RemoteAddrValve`.
