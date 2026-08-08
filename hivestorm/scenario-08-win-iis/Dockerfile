# Hivestorm HS21 — Windows Server-Core + IIS + PHP free-roam (Win10 stand-in).
#
# Build contract:
#   python -m hivestorm.common.roles --scenario 08 --seed $RANDOM \
#       --out hivestorm/scenario-08-win-iis/build/roles.json \
#       --render-task hivestorm/scenario-08-win-iis/task.md
#   docker build hivestorm/scenario-08-win-iis
#
# Base image ships IIS preinstalled; PHP is mocked via dropped files (scoring
# is about file/ini state, not interpreter behavior).

FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

# BASELINE TLS -- environment, not misconfiguration, hence a separate layer
# ahead of seed.ps1.
#
# verify.ps1 grades "Require SSL" on the default site (iis_ssl_required), and
# the image used to ship a single http:*:80 binding and no certificate. On that
# box the check and the task brief contradicted each other: satisfying the
# check turns every request into 403.4 (SSL required, nothing listening on
# 443), which breaks the brief's promise that the default site still serves a
# response. Verified on the old image -- Require SSL took http://localhost/
# from 200 to 403.
#
# Staging a self-signed certificate and an https:*:443 binding here makes both
# hold simultaneously, which is also what the real hardening looks like: TLS is
# available, the intruder simply left cleartext acceptable, and remediation is
# to require the transport that already exists.
RUN $c = New-SelfSignedCertificate -DnsName 'localhost' -CertStoreLocation 'Cert:\LocalMachine\My'; \
    Import-Module WebAdministration; \
    New-WebBinding -Name 'Default Web Site' -Protocol https -Port 443 -IPAddress '*'; \
    New-Item -Path "IIS:\SslBindings\0.0.0.0!443" -Value $c | Out-Null

COPY build/roles.json C:/ProgramData/sysrepair/roles.json
COPY seed.ps1         C:/ProgramData/sysrepair/seed.ps1

RUN C:\ProgramData\sysrepair\seed.ps1; \
    Remove-Item C:\ProgramData\sysrepair\seed.ps1

EXPOSE 80 443

CMD ["powershell", "-NoProfile", "-Command", "Start-Service W3SVC; while ($true) { Start-Sleep 3600 }"]
