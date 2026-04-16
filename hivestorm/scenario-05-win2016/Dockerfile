# Hivestorm HS20 — Windows Server 2016 free-roam.
#
# Build contract:
#   python -m hivestorm.common.roles --scenario 05 --seed $RANDOM \
#       --out hivestorm/scenario-05-win2016/build/roles.json \
#       --render-task hivestorm/scenario-05-win2016/task.md
#   docker build hivestorm/scenario-05-win2016

FROM mcr.microsoft.com/windows/servercore:ltsc2016

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

COPY build/roles.json C:/ProgramData/sysrepair/roles.json
COPY seed.ps1         C:/ProgramData/sysrepair/seed.ps1

RUN C:\ProgramData\sysrepair\seed.ps1; \
    Remove-Item C:\ProgramData\sysrepair\seed.ps1

CMD ["powershell", "-NoProfile", "-Command", "while ($true) { Start-Sleep 3600 }"]
