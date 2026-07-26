$ErrorActionPreference = 'Continue'
Start-Service sshd
Start-Service WinRM
# Launch Elasticsearch in the background so the JVM is a detached child, not PID 1.
Start-Process -FilePath 'C:\elasticsearch-1.6.0\bin\elasticsearch.bat' -WindowStyle Hidden
# Hold PID 1 open with an idle loop so restarting ES never kills the container.
while ($true) { Start-Sleep -Seconds 60 }
