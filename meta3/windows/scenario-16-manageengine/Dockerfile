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

# Install installer + setup.iss, run silent install, then relax the service
# account to LOCAL SERVICE (exactly mirrors scripts/installs/install_manageengine.bat
# from metasploitable3 master).
# Source URL: https://metasploitable-binaries.s3.amazonaws.com/metasploitable3/ManageEngine_DesktopCentral.exe
COPY scenario-16-manageengine/setup.iss C:/setup.iss
COPY shared/downloads/ManageEngine_DesktopCentral.exe C:/dc9.exe
RUN $p = Start-Process -FilePath 'C:\dc9.exe' -ArgumentList '/w','/s','/f1C:\setup.iss' -PassThru ; \
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

# One-time licence registration. Desktop Central 9 will not start until its
# licence agreement has been answered and lib\AdventNetLicense.xml exists, and
# the wizard that produces that file can only be answered by a JVM whose
# System.in is a real handle -- which the bundled Tanuki wrapper never provides,
# in service mode or in `DCService.bat -c` console mode alike. dc-register.bat
# carries the full measurement and the exact failure chain; the short version is
# that every unanswered prompt yields a null from CMDClass.getInput() and the
# product dies with a NullPointerException at CMDClass.java:217 that cascades
# through Wield.isBare into "Problem while Starting Server".
#
# This is a BUILD-time step on purpose. What it produces is two plain files
# under C:\ManageEngine\DesktopCentral_Server\lib (AdventNetLicense.xml, a copy
# of the shipped Free.xml, and an updated petinfo.dat), and plain files survive
# into the running container -- unlike the volume-root DACL that scenario-14 has
# to re-apply from its entrypoint. The registered state is not bound to the
# machine name or SID, so it is still valid when the container is given new
# ones at run time; the smoke start below is what proves that end to end.
#
# Every descendant has to be reaped before the step ends. Docker tracks a RUN's
# children through a Job object, so the layer is not committed while any of them
# is alive -- and DCStarter launches the bundled PostgreSQL under a cmd.exe of
# its own, which never exits on its own. Leaving it running hangs the build
# forever with no output; killing the JVM alone is not enough.
COPY scenario-16-manageengine/dc-register.bat C:/dc-register.bat
RUN $ans = 'C:\dc-eula-answers.txt' ; \
    $sw = New-Object System.IO.StreamWriter($ans, $false, [System.Text.Encoding]::ASCII) ; \
    $chunk = ('y' + [char]13 + [char]10) * 1000 ; \
    for ($i = 0; $i -lt 500; $i++) { $sw.Write($chunk) } ; \
    $sw.Close() ; \
    $lic = 'C:\ManageEngine\DesktopCentral_Server\lib\AdventNetLicense.xml' ; \
    $p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','C:\dc-register.bat > C:\dc-register.log 2>&1' -NoNewWindow -PassThru ; \
    $t0 = Get-Date ; \
    while (((Get-Date) - $t0).TotalSeconds -lt 480 -and -not (Test-Path $lic)) { Start-Sleep 5 ; if ($p.HasExited) { break } } ; \
    Start-Sleep 5 ; \
    $ok = Test-Path $lic ; \
    Get-Process java, postgres, wrapper -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue ; \
    foreach ($c in @(Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" -ErrorAction SilentlyContinue)) { \
        if ("$($c.CommandLine)" -like '*postgres*' -or "$($c.CommandLine)" -like '*dc-register*') { \
            Stop-Process -Id $c.ProcessId -Force -ErrorAction SilentlyContinue \
        } \
    } ; \
    Start-Sleep 5 ; \
    if (-not $ok) { Get-Content 'C:\dc-register.log' -Tail 40 -ErrorAction SilentlyContinue ; throw 'licence registration produced no lib\AdventNetLicense.xml' } ; \
    Remove-Item 'C:\dc-eula-answers.txt','C:\dc-register.bat','C:\dc-register.log' -Force -ErrorAction SilentlyContinue

# Smoke start. Bring the product up once here and require a real HTTP 200 from
# the admin UI, so a Desktop Central that cannot serve fails the BUILD instead
# of shipping an image whose regression check can never pass. It also leaves the
# bundled PostgreSQL initialised, which is most of the first-start cost.
RUN Start-Service 'MEDCServerComponent-Apache' ; \
    Start-Service 'DesktopCentralServer' ; \
    $ok = $false ; $t0 = Get-Date ; \
    while (((Get-Date) - $t0).TotalSeconds -lt 600 -and -not $ok) { \
        Start-Sleep 10 ; \
        try { if ((Invoke-WebRequest 'http://localhost:8020/' -UseBasicParsing -TimeoutSec 10).StatusCode -eq 200) { $ok = $true } } catch { } \
    } ; \
    if (-not $ok) { Get-Content 'C:\ManageEngine\DesktopCentral_Server\logs\wrapper.log' -Tail 40 -ErrorAction SilentlyContinue ; throw 'Desktop Central did not serve HTTP 200 on 8020' } ; \
    Stop-Service 'DesktopCentralServer' -Force -ErrorAction SilentlyContinue ; \
    Stop-Service 'MEDCServerComponent-Apache' -Force -ErrorAction SilentlyContinue ; \
    Start-Sleep 20 ; \
    Get-Process java, postgres, wrapper -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue ; \
    Start-Sleep 5

# Hand the three Desktop Central services back to the SCM as Automatic, in the
# LAST RUN of the build so no intermediate build container is affected. They
# were Manual only because a build-time auto-start used to wedge on the licence
# prompt; that prompt is gone now.
#
# This is a startup-latency fix, not cosmetics. Left on Manual, the JVM does not
# begin booting until the CMD reaches it -- and the CMD gets there only after
# Start-Service WinRM, which alone can take ten seconds or more. Automatic lets
# the SCM launch all three concurrently with the rest of container boot, which
# is what gets the admin UI answering 200 before the harness scores the box. The
# CMD still calls Start-Service on them: it is idempotent, and it is what makes
# a solution that stops the product see it stay stopped.
RUN $services = Get-CimInstance Win32_Service ; \
    foreach ($svcName in @('DesktopCentralServer','MEDC Server Component - Notification Server','MEDCServerComponent-Apache')) { \
        $svc = $services | Where-Object { $_.Name -eq $svcName } ; \
        if (-not $svc) { throw 'service not found' } ; \
        $r = Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{ StartMode = 'Automatic' } ; \
        if ($r.ReturnValue -ne 0) { throw ('Win32_Service.Change failed rc=' + $r.ReturnValue) } \
    }

EXPOSE 8020 8040 8383 22 5985

# Readiness belongs to the container, not to the grader. Desktop Central needs
# roughly twenty seconds of JVM and Tomcat startup after the SCM launches it,
# and Apache is bound to 8020 answering 503 the whole time -- so a scorer that
# runs the moment the container is "running" sees a 503 and records a false
# regression. Inspect starts sandboxes with `docker compose up --detach --wait`,
# which blocks until every container with a healthcheck reports healthy, so
# declaring readiness here makes the box genuinely up before anything looks at
# it. verify.ps1 stays strict: it still demands one real 200, first try, no
# retry and no sleep of its own.
#
# Health is only consulted while the sandbox is coming up
# (compose_check_running filters on running/exited, never on health), so a
# solution that decommissions Desktop Central and leaves the container unhealthy
# is not penalised for it.
HEALTHCHECK --interval=10s --timeout=10s --start-period=20s --retries=40 \
    CMD ["powershell", "-NoProfile", "-Command", "try { if ((Invoke-WebRequest 'http://localhost:8020/' -UseBasicParsing -TimeoutSec 5).StatusCode -eq 200) { exit 0 } } catch { }; exit 1"]
# Start sshd + WinRM, then make sure all three Desktop Central services are up
# (the SCM has normally started them already). DesktopCentralServer is an
# ordinary Windows service here: with the licence registered there is nothing
# left for it to read from stdin. PID 1 is the idle supervisor loop, so nothing
# a solution stops or restarts can kill the container.
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service 'MEDC Server Component - Apache'; Start-Service 'MEDC Server Component - Notification Server'; Start-Service DesktopCentralServer; while ($true) { Start-Sleep 60 }"]
