# Hivestorm HS23 scenario-11 — Windows Server-Core 2019, DC/DNS-style
# hardening (registry-state only).
#
# AD DS, Certificate Services, and Kerberos KDC roles cannot run inside a
# Server-Core container, and the DNS Server feature cannot be reliably
# Install-WindowsFeature'd in this base image. This scenario therefore scores
# on registry / Local Security Policy / auditpol state — the same state GPO
# would write on a real DC.
#
# Build contract:
#   python -m hivestorm.common.roles --scenario 11 --seed $RANDOM \
#       --out hivestorm/scenario-11-win-dc-dns/build/roles.json \
#       --render-task hivestorm/scenario-11-win-dc-dns/task.md
#   docker build hivestorm/scenario-11-win-dc-dns
FROM mcr.microsoft.com/windows/servercore:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

COPY build/roles.json C:/ProgramData/sysrepair/roles.json
COPY seed.ps1         C:/ProgramData/sysrepair/seed.ps1

RUN C:\ProgramData\sysrepair\seed.ps1; \
    Remove-Item C:\ProgramData\sysrepair\seed.ps1

CMD ["powershell", "-NoProfile", "-Command", "while ($true) { Start-Sleep 3600 }"]
