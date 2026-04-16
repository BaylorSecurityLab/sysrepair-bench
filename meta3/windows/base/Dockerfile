# syntax=docker/dockerfile:1
# sysrepair/meta3-win-base — shared Server Core base for every meta3-win-NN scenario.
# Mirrors the common prep that upstream metasploitable3 does on Win2k8R2 before any
# vulnerable app is installed: firewall off, RDP on, OpenSSH + WinRM reachable,
# a local admin the benchmark agent can log in as.
ARG BASE=mcr.microsoft.com/windows/servercore:ltsc2019
FROM ${BASE}

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# --- baseline OS config (upstream: disable_firewall.bat + enable-rdp.bat) ---
# NOTE: MpsSvc (Windows Defender Firewall) is not running at image-build time on
# Server Core, so `netsh advfirewall` fails. We disable the firewall profiles via
# the registry directly instead, and register the RDP allow rule the same way.
RUN reg add 'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'   /v EnableFirewall /t REG_DWORD /d 0 /f ; \
    reg add 'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile' /v EnableFirewall /t REG_DWORD /d 0 /f ; \
    reg add 'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'   /v EnableFirewall /t REG_DWORD /d 0 /f ; \
    reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f

# --- benchmark admin user (upstream default: vagrant/vagrant, weak on purpose) ---
RUN net user vagrant 'vagrant' /add ; \
    net localgroup Administrators vagrant /add ; \
    net accounts /maxpwage:unlimited

# --- OpenSSH Server (primary agent entry point, host maps 2222->22) ---
# NOTE: Add-WindowsCapability doesn't work inside Server Core containers because
# DISM's feature-store services aren't running at build time. We install the
# PowerShell/Win32-OpenSSH release directly from GitHub instead — same sshd.exe
# Microsoft ships via the capability, just delivered as a zip.
RUN Invoke-WebRequest -Uri 'https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.5.0.0p1-Beta/OpenSSH-Win64.zip' -OutFile 'C:\ossh.zip' -UseBasicParsing ; \
    Expand-Archive -Path 'C:\ossh.zip' -DestinationPath 'C:\Program Files\' -Force ; \
    Rename-Item 'C:\Program Files\OpenSSH-Win64' 'C:\Program Files\OpenSSH' ; \
    Remove-Item 'C:\ossh.zip' ; \
    powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\Program Files\OpenSSH\install-sshd.ps1' ; \
    Set-Service -Name sshd -StartupType Automatic ; \
    New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null ; \
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force | Out-Null

# --- WinRM HTTP listener (secondary agent entry point, 5985) ---
RUN winrm quickconfig -quiet -force ; \
    winrm set winrm/config/service '@{AllowUnencrypted=\"true\"}' ; \
    winrm set winrm/config/service/auth '@{Basic=\"true\"}'

# --- .NET 3.5 — several scenarios (ManageEngine, WAMP, GlassFish console) need it ---
RUN dism /online /enable-feature /featurename:NetFx3 /all /NoRestart ; exit 0

EXPOSE 22 3389 5985
# Keep the container alive; individual scenarios override this when they start a real service.
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; while ($true) { Start-Sleep 60 }"]
