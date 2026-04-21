# syntax=docker/dockerfile:1
# meta3-win-16-manageengine — ManageEngine Desktop Central 9 FileUploadServlet arbitrary upload (CVE-2015-8249)
#
# Upstream Rapid7 pinned Desktop Central build 9.1.0_91097. The vendor archive
# (archives.manageengine.com/desktop-central/9.1.0_build_91097/…) no longer serves
# the full installer, but Rapid7 mirrors it on their own S3 bucket under a
# version-less object key (`metasploitable3/ManageEngine_DesktopCentral.exe`) —
# that mirror is what `scripts/installs/install_manageengine.bat` downloads from
# in upstream metasploitable3. We reuse the same URL and the same
# InstallShield response file (`setup.iss`) so the silent install matches the
# shape Rapid7 exercises.
#
# FRICTION NOTE: the installer is a ~128MB InstallAnywhere bundle that writes to
# C:\ManageEngine and registers three services (DesktopCentralServer,
# MEDCServerComponent-Apache, MEDC Server Component - Notification Server).
# It runs to completion most of the time on Server Core ltsc2019, but if the
# Windows Installer service fails during `start /WAIT`, rebuild inside Hyper-V
# isolation (--isolation=hyperv) and allow the RUN step up to ~15 minutes.
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

ARG DC9_URL=https://metasploitable-binaries.s3.amazonaws.com/metasploitable3/ManageEngine_DesktopCentral.exe

# Download installer + setup.iss, run silent install, then relax the service
# account to LOCAL SERVICE (exactly mirrors scripts/installs/install_manageengine.bat
# from metasploitable3 master).
COPY setup.iss C:/setup.iss
RUN [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; \
    (New-Object System.Net.WebClient).DownloadFile($env:DC9_URL, 'C:\dc9.exe') ; \
    Start-Process -FilePath 'C:\dc9.exe' -ArgumentList '/w','/s','/f1C:\setup.iss' -Wait ; \
    Remove-Item 'C:\dc9.exe'

# Stop the services so we can reconfigure them, grant LOCAL SERVICE full control
# on C:\ManageEngine, rebind the services to LOCAL SERVICE, then leave them
# stopped — the CMD below will start them at container start.
RUN Stop-Service 'DesktopCentralServer' -ErrorAction SilentlyContinue ; \
    Stop-Service 'MEDC Server Component - Apache' -ErrorAction SilentlyContinue ; \
    Stop-Service 'MEDC Server Component - Notification Server' -ErrorAction SilentlyContinue ; \
    cmd /c 'icacls "C:\ManageEngine" /grant "NT Authority\LOCAL SERVICE:(OI)(CI)F" /T' ; \
    cmd /c 'sc config "DesktopCentralServer" obj= "NT Authority\LOCAL SERVICE" type= own start= auto' ; \
    cmd /c 'sc config "MEDC Server Component - Notification Server" obj= "NT Authority\LOCAL SERVICE" type= own start= auto' ; \
    cmd /c 'sc config "MEDCServerComponent-Apache" obj= "NT Authority\LOCAL SERVICE" type= own start= auto'
# Firewall is disabled in the base image; no explicit allow rules required.

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 8020 8040 8383 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service 'MEDC Server Component - Apache'; Start-Service 'MEDC Server Component - Notification Server'; Start-Service DesktopCentralServer; while ($true) { Start-Sleep 60 }"]
