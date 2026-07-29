$ErrorActionPreference = 'Continue'
Start-Service sshd
Start-Service WinRM
# Launch Jenkins as a detached child so PID 1 stays the idle loop below; the solution
# stops this java process and relaunches it with the fixed WAR + security enabled.
Start-Process -FilePath 'C:\Java\jdk8u402-b06-jre\bin\java.exe' -WindowStyle Hidden -ArgumentList @(
    '-Djenkins.install.runSetupWizard=false',
    '-DJENKINS_HOME=C:\jenkins\home',
    '-jar', 'C:\jenkins\jenkins.war', '--httpPort=8080'
)
while ($true) { Start-Sleep -Seconds 60 }
