# Hivestorm HS20 — Windows Server 2019 free-roam.
#
# Build contract:
#   python -m hivestorm.common.roles --scenario 04 --seed $RANDOM \
#       --out hivestorm/scenario-04-win2019/build/roles.json \
#       --render-task hivestorm/scenario-04-win2019/task.md
#   docker build hivestorm/scenario-04-win2019

FROM mcr.microsoft.com/windows/servercore:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

COPY build/roles.json C:/ProgramData/sysrepair/roles.json
COPY seed.ps1         C:/ProgramData/sysrepair/seed.ps1

RUN C:\ProgramData\sysrepair\seed.ps1; \
    Remove-Item C:\ProgramData\sysrepair\seed.ps1

CMD ["powershell", "-NoProfile", "-Command", "while ($true) { Start-Sleep 3600 }"]
