$ErrorActionPreference = 'Continue'
Start-Service sshd
Start-Service WinRM
$env:Path = 'C:\Java\jdk8u402-b06\bin;' + $env:Path
$env:AS_JAVA = 'C:\Java\jdk8u402-b06'
# start-domain (no --verbose) launches domain1 as a detached child java process and
# returns, so PID 1 remains this idle loop. asadmin/restart-domain from the solution
# can then cycle the domain without taking the container down.
& C:\glassfish4\glassfish\bin\asadmin.bat start-domain domain1
while ($true) { Start-Sleep -Seconds 60 }
