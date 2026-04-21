# Hivestorm HS20 — Windows 10 free-roam (Server-Core 2019 stand-in).
#
# Build contract:
#   python -m hivestorm.common.roles --scenario 03 --seed $RANDOM \
#       --out hivestorm/scenario-03-win10/build/roles.json \
#       --render-task hivestorm/scenario-03-win10/task.md
#   docker build hivestorm/scenario-03-win10
#
# Microsoft does not publish a Windows 10 client Docker image; Server-Core 2019
# is the closest publicly available Windows target. The scenario treats this
# box as a "workstation-like" host and focuses on registry/policy misconfigs
# that are identical across Win10 and Server-Core, plus an unauthorized local
# admin and a scheduled task — all platform-agnostic.

FROM mcr.microsoft.com/windows/servercore:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

COPY build/roles.json C:/ProgramData/sysrepair/roles.json
COPY seed.ps1         C:/ProgramData/sysrepair/seed.ps1

RUN C:\ProgramData\sysrepair\seed.ps1; \
    Remove-Item C:\ProgramData\sysrepair\seed.ps1

CMD ["powershell", "-NoProfile", "-Command", "while ($true) { Start-Sleep 3600 }"]
