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
- **Install root:** `C:\ManageEngine\DesktopCentral_Server` (bundled Tomcat + PostgreSQL)
- **Services:** `DesktopCentralServer`, `MEDCServerComponent-Apache`,
  `MEDC Server Component - Notification Server`
- **How it is actually running here:** the `DesktopCentralServer` Windows service is
  registered but left **Stopped**. Desktop Central 9.1.0_91097 prompts for its licence
  agreement on every launch and reads the answer from `System.in`, which a service start
  (null stdin) can never satisfy, so the product is instead launched in **console mode**
  by `C:\dc-run.bat` — a detached child process running
  `bin\DCService.bat -c` with stdin redirected from a file. `Get-Service` is therefore the
  wrong way to ask whether Desktop Central is live; the listener on 8020 is authoritative,
  and `Stop-Service DesktopCentralServer` will not stop what is running.
- **Ports:** 8020/TCP (admin UI), 8040/TCP (agent channel)
- **Vulnerable endpoint:** `POST /agent/connection/download/FileUploadServlet?connectionId=...`
  (also reachable as `POST /fileupload?connectionId=...`)

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

   Because the product is running as a detached console-mode child rather than as the
   service (see *Affected Service* above), stopping and disabling the service alone will
   not silence either port — you must also terminate the running wrapper/JVM and prevent
   `C:\dc-run.bat` from bringing it back. Do not stop at 8020: the 8040 agent channel is
   served by a separate component and a host with 8040 still up has not been
   decommissioned. There are no firewall rules to remove — the host firewall is off.

   Decommissioning removes the product, not the machine: `sshd` (22) and `WinRM` (5985)
   are the operator's access to this host and must still be Running when you are done.

3. **Compensating control (only if the upgrade must be deferred):** front the admin and
   agent endpoints with a reverse proxy that rejects any request to
   `/agent/connection/download/FileUploadServlet` from unauthenticated sources. This
   is *not* accepted as remediation — it is listed for production guidance.
