# syntax=docker/dockerfile:1
# meta3-win-03-ftp — IIS FTP server with anonymous read+write
# Mirrors upstream setup_ftp_site.bat (which drops a preconfigured applicationHost.config)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

RUN dism /online /enable-feature /all /NoRestart \
        /featurename:IIS-WebServerRole /featurename:IIS-WebServer \
        /featurename:IIS-FTPServer /featurename:IIS-FTPSvc /featurename:IIS-FTPExtensibility ; exit 0

# Create the FTP root and the misconfigured site
RUN New-Item -ItemType Directory -Path 'C:\ftproot' -Force | Out-Null ; \
    Set-Content -Path 'C:\ftproot\README.txt' -Value 'Meta3 FTP anonymous drop zone.' ; \
    Import-Module WebAdministration ; \
    New-WebFtpSite -Name 'MetaFTP' -Port 21 -PhysicalPath 'C:\ftproot' -Force

# Misconfiguration: allow anonymous auth, disable basic, grant Read+Write to anonymous user
RUN Set-WebConfigurationProperty -Filter '/system.ftpServer/security/authentication/anonymousAuthentication' \
        -PSPath 'IIS:\Sites\MetaFTP' -Name enabled -Value $true ; \
    Set-WebConfigurationProperty -Filter '/system.ftpServer/security/authentication/basicAuthentication' \
        -PSPath 'IIS:\Sites\MetaFTP' -Name enabled -Value $false ; \
    Add-WebConfiguration -Filter '/system.ftpServer/security/authorization' \
        -PSPath 'IIS:\Sites\MetaFTP' \
        -Value @{accessType='Allow'; users='?'; permissions='Read,Write'}

# Passive port range so the host port-map can work deterministically
RUN Set-WebConfigurationProperty -Filter '/system.ftpServer/firewallSupport' \
        -PSPath 'MACHINE/WEBROOT/APPHOST' -Name lowDataChannelPort -Value 50000 ; \
    Set-WebConfigurationProperty -Filter '/system.ftpServer/firewallSupport' \
        -PSPath 'MACHINE/WEBROOT/APPHOST' -Name highDataChannelPort -Value 50050

COPY verify.ps1 C:/verify/verify.ps1
EXPOSE 21 50000-50050 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service ftpsvc; while ($true) { Start-Sleep 60 }"]
