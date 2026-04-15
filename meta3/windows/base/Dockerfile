# syntax=docker/dockerfile:1
# sysrepair/meta3-win-base — shared Server Core base for every meta3-win-NN scenario.
# Mirrors the common prep that upstream metasploitable3 does on Win2k8R2 before any
# vulnerable app is installed: firewall off, RDP on, OpenSSH + WinRM reachable,
# a local admin the benchmark agent can log in as.
ARG BASE=mcr.microsoft.com/windows/servercore:ltsc2019
FROM ${BASE}

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# --- baseline OS config (upstream: disable_firewall.bat + enable-rdp.bat) ---
RUN netsh advfirewall set allprofiles state off ; \
    reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f ; \
    netsh advfirewall firewall add rule name='RDP-3389' dir=in action=allow protocol=TCP localport=3389

# --- benchmark admin user (upstream default: vagrant/vagrant, weak on purpose) ---
RUN net user vagrant 'vagrant' /add ; \
    net localgroup Administrators vagrant /add ; \
    net accounts /maxpwage:unlimited

# --- OpenSSH Server (primary agent entry point, host maps 2222->22) ---
RUN Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 ; \
    Set-Service -Name sshd -StartupType Automatic ; \
    New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 ; \
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force

# --- WinRM HTTP listener (secondary agent entry point, 5985) ---
RUN winrm quickconfig -quiet -force ; \
    winrm set winrm/config/service '@{AllowUnencrypted=\"true\"}' ; \
    winrm set winrm/config/service/auth '@{Basic=\"true\"}'

# --- .NET 3.5 — several scenarios (ManageEngine, WAMP, GlassFish console) need it ---
RUN dism /online /enable-feature /featurename:NetFx3 /all /NoRestart ; exit 0

EXPOSE 22 3389 5985
# Keep the container alive; individual scenarios override this when they start a real service.
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; while ($true) { Start-Sleep 60 }"]
