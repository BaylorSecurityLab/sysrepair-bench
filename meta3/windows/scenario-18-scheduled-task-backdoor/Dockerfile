# syntax=docker/dockerfile:1
# meta3-win-18-scheduled-task-backdoor — hidden scheduled task launching a payload from C:\Users\Public on logon + hourly
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Drop the "payload" in a world-writable directory (T1074 staging surface) and
# register a scheduled task that runs it under SYSTEM hourly and at every logon.
# Name is chosen to blend in with benign Microsoft tasks — 'Windows Update Assistant'.
# Stage the payload script and grant BUILTIN\Users write access (T1074 staging surface).
RUN New-Item -ItemType Directory -Path C:\Users\Public\Updater -Force | Out-Null
COPY updater.ps1 C:/Users/Public/Updater/updater.ps1
RUN icacls C:\Users\Public\Updater /grant 'BUILTIN\Users:(OI)(CI)M' /T

# Task Scheduler service runs at container runtime but not at build time.


EXPOSE 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; schtasks.exe /Create /TN '\\Microsoft\\Windows\\UpdateOrchestrator\\Windows Update Assistant' /TR 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Users\\Public\\Updater\\updater.ps1' /SC HOURLY /RU SYSTEM /RL HIGHEST /F; while ($true) { Start-Sleep 60 }"]
