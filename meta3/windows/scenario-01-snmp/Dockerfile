# syntax=docker/dockerfile:1
# meta3-win-01-snmp — SNMP agent with 'public' community string
# Faithful to upstream scripts/installs/setup_snmp.bat
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# SNMP is a deprecated Windows Capability on modern Server Core — install via DISM/Add-WindowsCapability
RUN Add-WindowsCapability -Online -Name 'SNMP.Client~~~~0.0.1.0' ; \
    Add-WindowsCapability -Online -Name 'SNMP.WMI.Provider~~~~0.0.1.0' ; \
    dism /online /enable-feature /featurename:SNMP /all /NoRestart ; exit 0

# Reproduce upstream registry config exactly (setup_snmp.bat):
#   - wipe PermittedManagers (accept from any host)
#   - disable authentication traps
#   - add ValidCommunities\public = READ-WRITE (4)
RUN reg delete 'HKLM\SYSTEM\CurrentControlSet\services\SNMP\Parameters\PermittedManagers' /va /f ; exit 0
RUN reg add 'HKLM\SYSTEM\CurrentControlSet\services\SNMP\Parameters' /v EnableAuthenticationTraps /t REG_DWORD /d 0 /f ; \
    reg add 'HKLM\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities' /v public /t REG_DWORD /d 4 /f ; \
    New-NetFirewallRule -DisplayName 'SNMP-161' -Direction Inbound -Protocol UDP -LocalPort 161 -Action Allow

COPY verify.ps1 C:/verify/verify.ps1
EXPOSE 161/udp 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service SNMP; while ($true) { Start-Sleep 60 }"]
