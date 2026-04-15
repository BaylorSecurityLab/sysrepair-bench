# syntax=docker/dockerfile:1
# meta3-win-16-manageengine — ManageEngine Desktop Central 9 FileUploadServlet arbitrary upload (CVE-2015-8249)
#
# FRICTION NOTE: ManageEngine_DesktopCentral_9_9.1.0.91097.exe is a 350MB InstallAnywhere
# bundle that writes to %ProgramFiles(x86)% and reports progress through Windows Installer.
# On Server Core it runs to completion roughly two times out of three — build in a Hyper-V
# VM the first time you generate this image, then `docker commit` the working layer. The
# Dockerfile below assumes the installer exits 0 and registers the ManageEngineDesktopCentral
# service; if it does not, extract the installer directory tree into C:\ManageEngine\DesktopCentral_Server
# manually and `docker cp` it in place of the `Start-Process` line.
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

ARG DC9_URL=https://archives.manageengine.com/desktop-central/9.1.0_build_91097/ManageEngine_DesktopCentral_9.exe

RUN Invoke-WebRequest -Uri $env:DC9_URL -OutFile 'C:\dc9.exe' -UseBasicParsing ; \
    Start-Process -FilePath 'C:\dc9.exe' -ArgumentList '-i','silent' -Wait ; \
    Remove-Item 'C:\dc9.exe' ; \
    # Open the listener port for the agent
    New-NetFirewallRule -DisplayName 'DC9-8020' -Direction Inbound -Protocol TCP -LocalPort 8020 -Action Allow ; \
    New-NetFirewallRule -DisplayName 'DC9-8040' -Direction Inbound -Protocol TCP -LocalPort 8040 -Action Allow

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 8020 8040 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service ManageEngineDesktopCentral; while ($true) { Start-Sleep 60 }"]
