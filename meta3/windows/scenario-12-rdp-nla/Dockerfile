# syntax=docker/dockerfile:1
# meta3-win-12-rdp-nla — RDP with Network Level Authentication disabled (pre-auth attack surface)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Enable RDP, then disable NLA so the RDP screen is reachable without authenticating first.
RUN Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0 ; \
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 0 ; \
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 1 ; \
    New-NetFirewallRule -DisplayName 'RDP-3389' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 3389 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service TermService; while ($true) { Start-Sleep 60 }"]
