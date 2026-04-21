$ErrorActionPreference = 'Continue'
Start-Service sshd
Start-Service WinRM
Start-Process -FilePath 'C:\Python311\python.exe' -ArgumentList 'C:\snmp\snmp_agent.py' -WindowStyle Hidden
while ($true) { Start-Sleep -Seconds 60 }
