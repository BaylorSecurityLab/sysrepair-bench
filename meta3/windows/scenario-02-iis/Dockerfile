# syntax=docker/dockerfile:1
# meta3-win-02-iis — IIS with directory browsing + HTTP TRACE method enabled
# Derived from upstream scripts/installs/setup_iis.bat (feature set) plus the
# misconfigurations that upstream ships in resources/iis/applicationHost.config.
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Upstream setup_iis.bat feature set (kept verbatim)
RUN dism /online /enable-feature /all /NoRestart \
        /featurename:IIS-WebServerRole /featurename:IIS-WebServer \
        /featurename:IIS-CommonHttpFeatures /featurename:IIS-ApplicationDevelopment \
        /featurename:IIS-ASPNET /featurename:IIS-NetFxExtensibility \
        /featurename:IIS-ASP /featurename:IIS-CGI \
        /featurename:IIS-ISAPIExtensions /featurename:IIS-ISAPIFilter \
        /featurename:IIS-ServerSideIncludes ; exit 0

# Misconfiguration: enable directory browsing on Default Web Site
RUN Import-Module WebAdministration ; \
    Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' \
        -PSPath 'IIS:\Sites\Default Web Site' -Name enabled -Value $true

# Misconfiguration: allow HTTP TRACE verb (default IIS blocks it via requestFiltering/verbs)
RUN Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' \
        -Filter '/system.webServer/security/requestFiltering/verbs' \
        -Name '.' -Value @{verb='TRACE'; allowed='true'}

# Drop a couple of harmless files so directory browsing has something to enumerate
RUN New-Item -ItemType Directory -Path 'C:\inetpub\wwwroot\reports' -Force | Out-Null ; \
    Set-Content -Path 'C:\inetpub\wwwroot\reports\q1.txt' -Value 'Q1 financials (placeholder)' ; \
    Set-Content -Path 'C:\inetpub\wwwroot\reports\q2.txt' -Value 'Q2 financials (placeholder)'

COPY verify.ps1 C:/verify/verify.ps1
EXPOSE 80 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service W3SVC; while ($true) { Start-Sleep 60 }"]
