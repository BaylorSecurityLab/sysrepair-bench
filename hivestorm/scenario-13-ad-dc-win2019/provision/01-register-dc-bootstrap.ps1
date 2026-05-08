$ErrorActionPreference = "Stop"

# Stage roles.json on the box (seeder + verifier read this path).
New-Item -ItemType Directory -Path "C:\ProgramData\sysrepair" -Force | Out-Null
Copy-Item "C:\Users\vagrant\provisioning\roles.json" `
          "C:\ProgramData\sysrepair\roles.json" -Force
icacls "C:\ProgramData\sysrepair\roles.json" /inheritance:r `
       /grant:r "Administrators:F" "SYSTEM:F" | Out-Null

$setupDir = "C:\hs13-setup"
New-Item -ItemType Directory -Path $setupDir -Force | Out-Null

# Stage every artifact the SYSTEM bootstrap task will consume. We copy these
# now (while the WinRM-driven provisioner is still alive as local vagrant) so
# bootstrap.ps1 can read them without any network access.
Copy-Item "C:\Users\vagrant\provisioning\dc-bootstrap.ps1" "$setupDir\bootstrap.ps1"   -Force
Copy-Item "C:\Users\vagrant\provisioning\seed.ps1"        "$setupDir\seed.ps1"        -Force
Copy-Item "C:\Users\vagrant\provisioning\vagrant_key.pub" "$setupDir\vagrant_key.pub" -Force

# Idempotency: if already a DC, marker may already be present from a prior
# run; ensure it's set so the wait-bootstrap stage short-circuits.
$isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
if ($isDC) {
    New-Item -ItemType File -Path "$setupDir\BOOTSTRAP_COMPLETE" -Force | Out-Null
    Write-Host "[01-register] already a DC; marker placed, exit"
    exit 0
}

if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
    Write-Host "[01-register] installing AD-Domain-Services role"
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
}

# Register the SYSTEM-context AtStartup task. Critical: bootstrap.ps1 must
# run as SYSTEM (no WinRM session) so that destroying the local SAM mid-run
# can't 401 the provisioner.
$action    = New-ScheduledTaskAction -Execute "powershell.exe" `
               -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$setupDir\bootstrap.ps1`""
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" `
               -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
               -StartWhenAvailable -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "hs13-bootstrap" `
  -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "[01-register] hs13-bootstrap startup task registered"
