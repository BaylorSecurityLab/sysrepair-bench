$ErrorActionPreference = 'Continue'
Start-Service sshd
Start-Service WinRM
# Launch Tomcat in the background so the JVM is a detached child, not PID 1.
Start-Process -FilePath 'C:\tomcat\bin\catalina.bat' -ArgumentList 'run' -WindowStyle Hidden
# Hold PID 1 open with an idle loop so restarting Tomcat never kills the container.
while ($true) { Start-Sleep -Seconds 60 }
