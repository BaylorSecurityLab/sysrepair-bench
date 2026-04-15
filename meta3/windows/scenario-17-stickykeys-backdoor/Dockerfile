# syntax=docker/dockerfile:1
# meta3-win-17-stickykeys-backdoor — sethc.exe replaced with cmd.exe (classic logon-screen SYSTEM shell)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Replace sethc.exe (Sticky Keys handler) with a copy of cmd.exe. At a locked/logon
# screen, pressing Shift five times launches sethc.exe under winlogon — which means
# cmd.exe runs as NT AUTHORITY\SYSTEM without authentication.
#
# takeown/icacls are required because sethc.exe is owned by TrustedInstaller.
RUN takeown /F C:\Windows\System32\sethc.exe ; \
    icacls C:\Windows\System32\sethc.exe /grant Administrators:F ; \
    Copy-Item -Path C:\Windows\System32\sethc.exe -Destination C:\Windows\System32\sethc.exe.bak -Force ; \
    Copy-Item -Path C:\Windows\System32\cmd.exe -Destination C:\Windows\System32\sethc.exe -Force

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 22 5985 3389
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service TermService; while ($true) { Start-Sleep 60 }"]
