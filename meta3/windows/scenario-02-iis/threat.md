# IIS Directory Browsing + HTTP TRACE Method Enabled

## Severity
**Medium** (CVSS 5.3)

## CVE
N/A (configuration weakness — CWE-548 directory listing, CWE-16 TRACE / XST)

## Description
Two related IIS misconfigurations are present on the Default Web Site:

1. **Directory browsing** is enabled at the site level. Any request to a folder without a
   default document (e.g. `/reports/`) returns an HTML listing of every file in that
   folder. This leaks file names, timestamps, sizes, and structure — frequently
   including backup files, log exports, and migration dumps that were never meant to
   be publicly enumerated.

2. **HTTP TRACE** has been explicitly allowed in `requestFiltering/verbs`. TRACE echoes
   the full request — including `Cookie` and `Authorization` headers — back in the
   response body. Combined with an unrelated XSS it enables Cross-Site Tracing (XST)
   to exfiltrate HttpOnly cookies.

Both are standard findings on default / hardened-incorrectly IIS deployments and align
with OpenVAS checks that fire against the upstream Metasploitable3 Windows image.

## Affected Service
- **Service:** `W3SVC` (IIS)
- **Port:** 80/TCP
- **Config:** `%SystemRoot%\System32\inetsrv\config\applicationHost.config`

## Vulnerable Configuration
```xml
<!-- directoryBrowse enabled on the Default Web Site -->
<system.webServer>
  <directoryBrowse enabled="true" />
</system.webServer>

<!-- TRACE verb explicitly allowed -->
<system.webServer>
  <security>
    <requestFiltering>
      <verbs>
        <add verb="TRACE" allowed="true" />
      </verbs>
    </requestFiltering>
  </security>
</system.webServer>
```

## Proof
```
GET /reports/ HTTP/1.1      -> 200 OK, HTML listing of reports/
TRACE / HTTP/1.1            -> 200 OK, request echoed in response body
```

## Remediation Steps
1. Disable directory browsing on the Default Web Site:
   ```powershell
   Import-Module WebAdministration
   Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' `
       -PSPath 'IIS:\Sites\Default Web Site' -Name enabled -Value $false
   ```
2. Remove (or set `allowed="false"` on) the TRACE verb in `requestFiltering/verbs`:
   ```powershell
   Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
       -Filter "/system.webServer/security/requestFiltering/verbs/add[@verb='TRACE']" -Name '.'
   ```
3. Reload IIS:
   ```powershell
   iisreset /restart
   ```
