# syntax=docker/dockerfile:1
# meta3-win-10-smbv1 — SMBv1 protocol enabled (EternalBlue precondition; CVE-2017-0144 exposure)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Enable the legacy SMBv1 server (off by default on modern Server Core)
RUN Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All -NoRestart ; \
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force ; \
    New-NetFirewallRule -DisplayName 'SMB-445' -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 445 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service LanmanServer; while ($true) { Start-Sleep 60 }"]
