@echo off
rem Runtime launcher for Desktop Central in console mode with file-redirected
rem stdin. The `<` redirection inside the bat is the only mechanism that
rem reliably pipes a newline to the Tanuki wrapper (v3.5.15) and through to
rem the JVM's System.in, which DC's DCStarter reads during its SLA prompt.
rem See the Dockerfile CMD section for the full rationale.
cd /d "C:\ManageEngine\DesktopCentral_Server\bin"
DCService.bat -c < "C:\dc-stdin.txt"
