# syntax=docker/dockerfile:1
# meta3-win-21-ssh-defaults — OpenSSH Server with default vagrant:vagrant credentials + unpinned/legacy version
#
# The Rapid7 metasploitable3-windows box ships OpenSSH-Win32 (from the PowerShell/Win32-OpenSSH
# releases) as the Vagrant provisioning channel. Rapid7 leaves vagrant:vagrant as a local admin
# and never updates the binary, which is exactly what the OpenVAS scan of the reference VM
# flagged (CVE-2016-1908, CVE-2016-6210/6515, CVE-2016-10009-12, CVE-2017-15906, CVE-2018-15473).
# The base image already installs OpenSSH; this scenario pins the version back to the legacy
# build Rapid7 ships and re-confirms the vagrant:vagrant credential pair.
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Remove the modern OpenSSH capability pulled in by the base image, drop in the legacy
# Win32-OpenSSH 7.1.0.0-p1-beta release (first Microsoft public build — what the Rapid7
# provisioner installs) and register it as the sshd service.
RUN Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue ; \
    Remove-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 -ErrorAction SilentlyContinue ; \
    Invoke-WebRequest -Uri 'https://github.com/PowerShell/Win32-OpenSSH/releases/download/v7.1.0.0p1-Beta/OpenSSH-Win64.zip' -OutFile 'C:\ossh.zip' -UseBasicParsing ; \
    Expand-Archive -Path 'C:\ossh.zip' -DestinationPath 'C:\Program Files\' -Force ; \
    Rename-Item 'C:\Program Files\OpenSSH-Win64' 'C:\Program Files\OpenSSH' ; \
    Remove-Item 'C:\ossh.zip' ; \
    powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\Program Files\OpenSSH\install-sshd.ps1'

# Re-assert vagrant:vagrant as a local admin (base image ships this user; make sure the
# password matches the Rapid7 default and the account can log in remotely via sshd).
RUN $pw = ConvertTo-SecureString 'vagrant' -AsPlainText -Force ; \
    if (-not (Get-LocalUser -Name 'vagrant' -ErrorAction SilentlyContinue)) { \
        New-LocalUser -Name 'vagrant' -Password $pw -PasswordNeverExpires -UserMayNotChangePassword \
    } else { \
        Set-LocalUser -Name 'vagrant' -Password $pw -PasswordNeverExpires $true \
    } ; \
    Add-LocalGroupMember -Group 'Administrators' -Member 'vagrant' -ErrorAction SilentlyContinue
# Firewall is disabled in the base image; no explicit allow rule required.

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; while ($true) { Start-Sleep 60 }"]
