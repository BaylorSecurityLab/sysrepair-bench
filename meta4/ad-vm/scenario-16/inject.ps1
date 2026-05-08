$ErrorActionPreference = 'Stop'

Set-Service Spooler -StartupType Automatic
Start-Service Spooler

$papKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
if (-not (Test-Path $papKey)) { New-Item -Path $papKey -Force | Out-Null }
Set-ItemProperty -Path $papKey -Name 'RestrictDriverInstallationToAdministrators' -Value 0 -Type DWord
Set-ItemProperty -Path $papKey -Name 'NoWarningNoElevationOnInstall' -Value 1 -Type DWord
Set-ItemProperty -Path $papKey -Name 'UpdatePromptSettings' -Value 2 -Type DWord

Restart-Service Spooler -Force
Write-Host "[inject-16] Spooler running + Point-and-Print at pre-KB5005010 defaults"
