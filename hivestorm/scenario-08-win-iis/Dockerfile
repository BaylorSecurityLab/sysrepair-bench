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

COPY build/roles.json C:/ProgramData/sysrepair/roles.json
COPY seed.ps1         C:/ProgramData/sysrepair/seed.ps1

RUN C:\ProgramData\sysrepair\seed.ps1; \
    Remove-Item C:\ProgramData\sysrepair\seed.ps1

EXPOSE 80 443

CMD ["powershell", "-NoProfile", "-Command", "Start-Service W3SVC; while ($true) { Start-Sleep 3600 }"]
