# syntax=docker/dockerfile:1
# meta3-win-03-ftp — IIS FTP server with anonymous read+write
# Mirrors upstream setup_ftp_site.bat (which drops a preconfigured applicationHost.config)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

RUN dism /online /enable-feature /all /NoRestart \
        /featurename:IIS-WebServerRole /featurename:IIS-WebServer \
        /featurename:IIS-FTPServer /featurename:IIS-FTPSvc /featurename:IIS-FTPExtensibility \
        /featurename:IIS-ManagementScriptingTools ; exit 0

# Create the FTP root and the misconfigured site
RUN New-Item -ItemType Directory -Path 'C:\ftproot' -Force | Out-Null ; \
    Set-Content -Path 'C:\ftproot\README.txt' -Value 'Meta3 FTP anonymous drop zone.' ; \
    Import-Module WebAdministration ; \
    New-WebFtpSite -Name 'MetaFTP' -Port 21 -PhysicalPath 'C:\ftproot' -Force

# Misconfiguration: allow anonymous auth, disable basic, allow plaintext (no SSL),
# and grant Read+Write to anonymous user.
# FTP site-level auth/SSL use "appcmd set site" (dot-path into ftpServer element);
# authorization uses "appcmd set config" (system.ftpServer/security/authorization section).
RUN cmd /c 'C:\Windows\System32\inetsrv\appcmd.exe set site "MetaFTP" /ftpServer.security.authentication.anonymousAuthentication.enabled:true' ; \
    cmd /c 'C:\Windows\System32\inetsrv\appcmd.exe set site "MetaFTP" /ftpServer.security.authentication.basicAuthentication.enabled:false' ; \
    cmd /c 'C:\Windows\System32\inetsrv\appcmd.exe set site "MetaFTP" /ftpServer.security.ssl.controlChannelPolicy:SslAllow /ftpServer.security.ssl.dataChannelPolicy:SslAllow' ; \
    cmd /c 'C:\Windows\System32\inetsrv\appcmd.exe set config "MetaFTP" /section:system.ftpServer/security/authorization /+[accessType=''Allow'',users=''?'',permissions=''Read,Write''] /commit:apphost'

# Passive port range so the host port-map can work deterministically
RUN cmd /c 'C:\Windows\System32\inetsrv\appcmd.exe set config /section:system.ftpServer/firewallSupport /lowDataChannelPort:50000 /highDataChannelPort:50050 /commit:apphost'

COPY verify.ps1 C:/verify/verify.ps1
EXPOSE 21 50000-50050 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service ftpsvc; while ($true) { Start-Sleep 60 }"]
