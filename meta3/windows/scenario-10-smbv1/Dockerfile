# syntax=docker/dockerfile:1
# meta3-win-10-smbv1 — SMBv1 protocol enabled (EternalBlue precondition; CVE-2017-0144 exposure)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Enable the legacy SMBv1 server (off by default on modern Server Core)
# Enable SMB1 feature via DISM, then force-enable SMB1 via registry (the PS cmdlet
# needs LanmanServer running, which isn't available at build time).
# DISM returns 3010 (restart required) on success — swallow it.
RUN dism /online /enable-feature /featurename:SMB1Protocol /all /NoRestart ; if ($LASTEXITCODE -eq 3010 -or $LASTEXITCODE -eq 0) { exit 0 } else { exit $LASTEXITCODE }
RUN reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v SMB1 /t REG_DWORD /d 1 /f
# Firewall is disabled in the base image; no explicit allow rule required.

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 445 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service LanmanServer; while ($true) { Start-Sleep 60 }"]
