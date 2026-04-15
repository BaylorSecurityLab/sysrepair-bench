# syntax=docker/dockerfile:1
# meta3-win-18-scheduled-task-backdoor — hidden scheduled task launching a payload from C:\Users\Public on logon + hourly
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Drop the "payload" in a world-writable directory (T1074 staging surface) and
# register a scheduled task that runs it under SYSTEM hourly and at every logon.
# Name is chosen to blend in with benign Microsoft tasks — 'Windows Update Assistant'.
RUN New-Item -ItemType Directory -Path C:\Users\Public\Updater -Force | Out-Null ; \
    Set-Content -Path C:\Users\Public\Updater\updater.ps1 -Value @' \
        # Operator beacon — writes a heartbeat file every run so incident response has \
        # something to pivot on. A real implant would call out to C2 here. \
        $stamp = Get-Date -Format o \
        Add-Content -Path C:\Users\Public\Updater\heartbeat.log -Value "$stamp beacon" \
    '@ ; \
    icacls C:\Users\Public\Updater /grant 'BUILTIN\Users:(OI)(CI)M' /T ; \
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\Public\Updater\updater.ps1' ; \
    $trigHour  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 1) ; \
    $trigLogon = New-ScheduledTaskTrigger -AtLogOn ; \
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest ; \
    $settings  = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries ; \
    Register-ScheduledTask -TaskName 'Windows Update Assistant' -TaskPath '\Microsoft\Windows\UpdateOrchestrator\' -Action $action -Trigger $trigHour,$trigLogon -Principal $principal -Settings $settings

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; while ($true) { Start-Sleep 60 }"]
