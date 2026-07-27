#Requires -RunAsAdministrator
<#
.SYNOPSIS
Restore baseline, stage a scenario, and inject its vuln on the meta3/windows-vm host.

.DESCRIPTION
Mirrors the "restore -> copy scenario into VM -> inject" half of
meta4/ad-vm/run-scenario.sh, but for a single AutomatedLab/Hyper-V VM driven via
PowerShell Direct (Invoke-LabCommand) rather than vagrant winrm.

Steps:
  1. Restore-LabBaseline.ps1  (hardened baseline).
  2. Copy scenario-NN/ into the VM at C:\sysrepair\scenario-NN.
  3. Run inject.ps1 inside the VM (introduces the live vuln + restarts the service).

Use Test-ScenarioGates.ps1 afterwards to score (verify-poc + verify-service).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d{2}$')][string] $Id,   # 10 | 11 | 12
    [string] $LabName = 'SysRepairMeta3',
    [string] $VmName  = 'META3WIN'
)

$ErrorActionPreference = 'Stop'
Import-Module AutomatedLab -ErrorAction Stop

# Map the two-digit id to the on-disk scenario directory.
$root = Split-Path $PSScriptRoot -Parent
$dir  = Get-ChildItem -Path $root -Directory -Filter "scenario-$Id-*" | Select-Object -First 1
if (-not $dir) { throw "[Invoke-Scenario] no scenario dir matching scenario-$Id-* under $root" }

# 1. reset to baseline
& (Join-Path $PSScriptRoot 'Restore-LabBaseline.ps1') -LabName $LabName -VmName $VmName

Import-Lab -Name $LabName -NoValidation

# 2. stage the scenario dir into the VM
$dest = "C:\sysrepair\$($dir.Name)"
Write-Host "[Invoke-Scenario] copying $($dir.Name) -> ${VmName}:$dest"
Invoke-LabCommand -ComputerName $VmName -ActivityName 'clean-scenario-dir' -ScriptBlock {
    param($d) if (Test-Path $d) { Remove-Item $d -Recurse -Force }
    New-Item -ItemType Directory -Path $d -Force | Out-Null
} -ArgumentList $dest
Copy-LabFileItem -Path (Join-Path $dir.FullName '*') -ComputerName $VmName -DestinationFolderPath $dest -Recurse

# 3. inject the vuln inside the VM
Write-Host "[Invoke-Scenario] injecting scenario $Id on $VmName"
Invoke-LabCommand -ComputerName $VmName -ActivityName "inject-$Id" -ScriptBlock {
    param($d)
    & (Join-Path $d 'inject.ps1')
} -ArgumentList $dest

Write-Host ""
Write-Host "========================================================================"
Write-Host " Scenario $Id staged and injected on $VmName."
Write-Host " Agent works over the SSH bridge (port 22). threat.md is in $dest."
Write-Host " Score with:  lab\Test-ScenarioGates.ps1 -Id $Id"
Write-Host "========================================================================"
