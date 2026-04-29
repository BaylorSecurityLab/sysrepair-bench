# syntax=docker/dockerfile:1
# meta3-win-21-ssh-defaults — OpenSSH Server with default vagrant:vagrant credentials + unpinned/legacy version
#
# The Rapid7 metasploitable3-windows box ships OpenSSH-Win32 (from the PowerShell/Win32-OpenSSH
# releases) as the Vagrant provisioning channel. Rapid7 leaves vagrant:vagrant as a local admin
# and never updates the binary, which is exactly what the OpenVAS scan of the reference VM
# flagged (CVE-2016-1908, CVE-2016-6210/6515, CVE-2016-10009-12, CVE-2017-15906, CVE-2018-15473).
# The base image already installs OpenSSH 9.5; this scenario downgrades to the legacy
# v7.7.2.0p1-Beta build (still vulnerable to CVE-2018-15473 user enumeration and others)
# and re-confirms the vagrant:vagrant credential pair.
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Base image already has Win32-OpenSSH 9.5 at C:\Program Files\OpenSSH with sshd
# registered as a service. Stop the service, wipe the directory, drop in the legacy
# 7.1.0.0-p1-beta release, and re-register sshd.
# sc.exe returns non-zero when the service doesn't exist; use cmd /c to swallow it.
RUN Stop-Service sshd -ErrorAction SilentlyContinue ; \
    cmd /c 'sc.exe delete sshd & exit /b 0' ; \
    Remove-Item -Recurse -Force 'C:\Program Files\OpenSSH' -ErrorAction SilentlyContinue ; \
    Invoke-WebRequest -Uri 'https://github.com/PowerShell/Win32-OpenSSH/releases/download/v7.7.2.0p1-Beta/OpenSSH-Win64.zip' -OutFile 'C:\ossh.zip' -UseBasicParsing ; \
    Expand-Archive -Path 'C:\ossh.zip' -DestinationPath 'C:\Program Files\' -Force ; \
    Rename-Item 'C:\Program Files\OpenSSH-Win64' 'C:\Program Files\OpenSSH' ; \
    Remove-Item 'C:\ossh.zip' ; \
    powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\Program Files\OpenSSH\install-sshd.ps1'

# Re-assert vagrant:vagrant as a local admin (base image ships this user; make sure the
# password matches the Rapid7 default and the account can log in remotely via sshd).
# Relax password policy so the intentionally-weak 'vagrant' password can be set,
# then create the vagrant:vagrant admin account matching the Rapid7 default.
RUN net accounts /minpwlen:0 /maxpwage:unlimited
RUN secedit /export /cfg C:\secpol.cfg ; \
    (Get-Content C:\secpol.cfg) -replace 'PasswordComplexity\s*=\s*1','PasswordComplexity = 0' | Set-Content C:\secpol.cfg ; \
    secedit /configure /db C:\secedit.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY ; \
    Remove-Item C:\secpol.cfg, C:\secedit.sdb -ErrorAction SilentlyContinue
RUN net user vagrant vagrant /add 2>&1 | Out-Null ; \
    net user vagrant vagrant ; \
    cmd /c 'net localgroup Administrators vagrant /add & exit /b 0'
# Firewall is disabled in the base image; no explicit allow rule required.


EXPOSE 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; while ($true) { Start-Sleep 60 }"]
