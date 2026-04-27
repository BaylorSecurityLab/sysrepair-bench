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
# The installer spawns the DesktopCentralServer java wrapper as a descendant
# before exiting, and PowerShell's `Start-Process -Wait` tracks descendants via
# a Job object — which means -Wait never returns because the service keeps
# running. We wait on the process PID directly via $p.WaitForExit() instead.
# Allow up to ~15 minutes for the install to finish.
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

ARG DC9_URL=https://metasploitable-binaries.s3.amazonaws.com/metasploitable3/ManageEngine_DesktopCentral.exe

# Download installer + setup.iss, run silent install, then relax the service
# account to LOCAL SERVICE (exactly mirrors scripts/installs/install_manageengine.bat
# from metasploitable3 master).
COPY setup.iss C:/setup.iss
RUN [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; \
    (New-Object System.Net.WebClient).DownloadFile($env:DC9_URL, 'C:\dc9.exe') ; \
    $p = Start-Process -FilePath 'C:\dc9.exe' -ArgumentList '/w','/s','/f1C:\setup.iss' -PassThru ; \
    if (-not $p.WaitForExit(900000)) { throw 'dc9.exe did not exit within 15 minutes' } ; \
    Remove-Item 'C:\dc9.exe'

# Stop the services so we can reconfigure them, grant LOCAL SERVICE full control
# on C:\ManageEngine, rebind the Apache + Notification services to LOCAL SERVICE,
# then leave them stopped — the CMD below will start them at container start.
# The DesktopCentralServer service is left registered but we never start it at
# runtime; instead the CMD launches the Tanuki wrapper in console mode via
# dc-run.bat so the JVM's System.in is attached to a file of newlines. See the
# CMD section below for the full rationale.
#
# StartMode=Manual across all three services is deliberate: Docker's
# intermediate build containers run the Windows SCM, so Automatic services
# would start (and the DC one would hang on EULA) before any subsequent RUN
# step could react. Manual keeps them inert until runtime.
#
# NOTE: sc.exe via `cmd /c "sc config ... obj= \"NT Authority\\LOCAL SERVICE\" ..."`
# loses its inner quotes through the docker-SHELL → powershell → cmd → sc hop,
# so sc sees `NT` as a flag and aborts. We use WMI (Win32_Service.Change) which
# takes the account name as a typed string argument and is immune to shell quoting.
RUN Stop-Service 'DesktopCentralServer' -ErrorAction SilentlyContinue ; \
    Stop-Service 'MEDC Server Component - Apache' -ErrorAction SilentlyContinue ; \
    Stop-Service 'MEDC Server Component - Notification Server' -ErrorAction SilentlyContinue ; \
    & icacls.exe 'C:\ManageEngine' /grant '*S-1-5-19:(OI)(CI)F' /T ; \
    $services = Get-CimInstance Win32_Service ; \
    foreach ($svcName in @('DesktopCentralServer','MEDC Server Component - Notification Server','MEDCServerComponent-Apache')) { \
        $svc = $services | Where-Object { $_.Name -eq $svcName } ; \
        if (-not $svc) { throw 'service not found' } ; \
        $r = Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{ StartMode = 'Manual'; ServiceType = [uint32]16; StartName = 'NT AUTHORITY\LocalService'; StartPassword = '' } ; \
        if ($r.ReturnValue -ne 0) { throw ('Win32_Service.Change failed rc=' + $r.ReturnValue) } \
    }
# Firewall is disabled in the base image; no explicit allow rules required.

# Runtime helpers for the foreground-DC launch pattern:
#   dc-run.bat   — cd's to bin\ and runs `DCService.bat -c < C:\dc-stdin.txt`
#   dc-stdin.txt — ~10k CRLFs; only the first is consumed by the EULA prompt,
#                  the rest sit in the pipe until DC's JVM hits EOF (never).
# Why: DC's Java entry point (com.adventnet.sym.start.DCStarter) prints its
# Software License Agreement on every launch and calls System.in.read(). DC
# 9.1.0_91097 does NOT persist EULA acceptance — so a Windows-service start
# (null stdin) hangs forever on that read. The Tanuki wrapper bundled with
# DC (Java Service Wrapper 3.5.15) predates Tanuki's wrapper.console_input
# property (added in 3.5.52), and upgrading the wrapper in-place is not
# supported by ManageEngine. The only path that reliably delivers bytes to
# the JVM's System.in is running the wrapper in console mode with
# shell-level `<` stdin redirection — hence the .bat + newlines file.
COPY dc-run.bat C:/dc-run.bat
COPY dc-stdin.txt C:/dc-stdin.txt


EXPOSE 8020 8040 8383 22 5985
# Start sshd + WinRM + the two real DC services (Apache reverse-proxy and
# Notification Server). Skip Start-Service on DesktopCentralServer; launch it
# as a foreground child via dc-run.bat instead so the JVM's System.in is the
# newlines file. PowerShell's supervisor loop keeps the container alive; the
# foreground wrapper runs detached in its own child process.
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service 'MEDC Server Component - Apache'; Start-Service 'MEDC Server Component - Notification Server'; Start-Process -FilePath C:/dc-run.bat -NoNewWindow; while ($true) { Start-Sleep 60 }"]
