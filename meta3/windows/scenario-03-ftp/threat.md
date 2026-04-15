# IIS FTP — Anonymous Authentication with Read+Write Authorization

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness — CWE-284 improper access control, CWE-287 weak authN)

## Description
The IIS FTP site `MetaFTP` on port 21 accepts **anonymous** logins and the single
authorization rule grants the anonymous user (`users="?"`) **Read and Write**
permissions. An unauthenticated attacker reaching TCP/21 can:

- List and download every file under the FTP root (`C:\ftproot`).
- Upload arbitrary content — useful for staging tooling on the host or for pivoting:
  if `C:\ftproot` happens to overlap with an IIS web root, uploaded files become
  directly reachable over HTTP.

Authentication is further weakened by `basicAuthentication` being disabled, meaning the
anonymous path is the only authentication path — operators cannot simply "add a
password" without re-enabling basic auth first.

This reproduces the configuration shipped by upstream Metasploitable3 via
`scripts/installs/setup_ftp_site.bat` and `resources/iis/applicationHost.config`.

## Affected Service
- **Service:** `ftpsvc` (IIS FTP Service)
- **Port:** 21/TCP (control), 50000-50050/TCP (passive data)
- **Site:** `MetaFTP`, physical path `C:\ftproot`

## Vulnerable Configuration
```xml
<site name="MetaFTP">
  <ftpServer>
    <security>
      <authentication>
        <anonymousAuthentication enabled="true" />
        <basicAuthentication    enabled="false" />
      </authentication>
      <authorization>
        <add accessType="Allow" users="?" permissions="Read, Write" />
      </authorization>
    </security>
  </ftpServer>
</site>
```

## Proof
```
ftp> open localhost 21
Name (localhost:user): anonymous
230 User logged in.
ftp> put payload.exe          # succeeds
```

## Remediation Steps
1. Disable anonymous authentication on `MetaFTP`:
   ```powershell
   Set-WebConfigurationProperty -Filter '/system.ftpServer/security/authentication/anonymousAuthentication' `
       -PSPath 'IIS:\Sites\MetaFTP' -Name enabled -Value $false
   ```
2. Remove the anonymous allow rule:
   ```powershell
   Clear-WebConfiguration -Filter '/system.ftpServer/security/authorization' -PSPath 'IIS:\Sites\MetaFTP'
   ```
3. Re-enable basic (or preferably IIS Manager) authentication and add a scoped allow
   rule for a named, least-privilege account. Require FTP over TLS
   (`/system.ftpServer/security/ssl @controlChannelPolicy="SslRequire"`).
4. Restart the service:
   ```powershell
   Restart-Service ftpsvc
   ```
