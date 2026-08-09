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

# EVERY Invoke-LabCommand scriptblock below ENDS BY EMITTING AN OBJECT, and that
# is load-bearing, not decoration. AutomatedLabWorker's Invoke-LWLabCommand
# decides whether a scriptblock ran by looking for a RunspaceId on the objects
# it returned (AutomatedLabWorker.psm1 ~5141):
#
#     $results = Invoke-Command @parameters
#     foreach ($remoteRunspace in $results.RunspaceId | Sort-Object -Unique) {
#         ... $internalSession.Remove(...)
#     }
#     $Retries--
#
# A scriptblock that writes only to the host (Write-Host) returns nothing, so
# $results.RunspaceId is empty, the session is never retired, and the loop runs
# the SAME scriptblock again -- InvokeLabCommandRetries times, which defaults to
# 3. MEASURED on META3WIN with two one-line scripts that append to a log:
# with 'exit 0' and without it, both logged 3 invocations. That is why the
# inject appeared three times in the transcript and why the second pass died in
# Restart-Service with "Time out has expired": it was bouncing LanmanServer
# again while the first bounce was still settling. Emitting one object ends the
# loop after a single pass. This applies to scenarios 10, 11 and 12 alike --
# their injects are all Write-Host-only and were all running up to three times.
Invoke-LabCommand -ComputerName $VmName -ActivityName 'clean-scenario-dir' -ScriptBlock {
    param($d) if (Test-Path $d) { Remove-Item $d -Recurse -Force }
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    "cleaned $d"
} -ArgumentList $dest
Copy-LabFileItem -Path (Join-Path $dir.FullName '*') -ComputerName $VmName -DestinationFolderPath $dest -Recurse

# 3. inject the vuln inside the VM
Write-Host "[Invoke-Scenario] injecting scenario $Id on $VmName"
Invoke-LabCommand -ComputerName $VmName -ActivityName "inject-$Id" -ScriptBlock {
    param($d)
    & (Join-Path $d 'inject.ps1')
    "inject.ps1 pass complete"
} -ArgumentList $dest

# 3b. Some vulnerabilities cannot be introduced without a boot. Scenario 10 is
# one: Windows registers the srv service (SMB 1.x server) only while booting,
# so enabling the SMB1Protocol feature with -NoRestart leaves
# Set-SmbServerConfiguration -EnableSMB1Protocol $true failing with "The
# specified service does not exist" and the box NOT vulnerable. An inject that
# needs a boot says so by dropping .reboot-required in its own directory; this
# is generic, so scenarios that do not need it pay nothing.
$needsReboot = Invoke-LabCommand -ComputerName $VmName -PassThru -ActivityName 'check-reboot-sentinel' -ScriptBlock {
    param($d) Test-Path -Path (Join-Path $d '.reboot-required')
} -ArgumentList $dest

if ($needsReboot) {
    Write-Host "[Invoke-Scenario] inject requested a reboot; restarting $VmName"
    Restart-LabVM -ComputerName $VmName -Wait
    Wait-LabVM -ComputerName $VmName -TimeoutInMinutes 10
    Write-Host "[Invoke-Scenario] resuming inject $Id after reboot"
    Invoke-LabCommand -ComputerName $VmName -ActivityName "inject-$Id-post-reboot" -ScriptBlock {
        param($d)
        & (Join-Path $d 'inject.ps1')
        "inject.ps1 post-reboot pass complete"
    } -ArgumentList $dest
}

# 3c. Readiness re-gate, same purpose as meta4/ad-vm's Invoke-ScenarioInject:
# never hand the agent a half-started box, because a PoC that fails against a
# service which merely has not finished starting grades as "blocked" -- the
# vulnerability would look remediated by the injector. The gate used here is
# the scenario's OWN verify-service.ps1, so it checks the right service and the
# right port (445 for 10/11, 3389 for 12) without this driver knowing which.
Write-Host "[Invoke-Scenario] re-checking readiness after inject"
$deadline = (Get-Date).AddSeconds(300)
$svcRc = 1
while ($true) {
    $svcRc = [int](Invoke-LabCommand -ComputerName $VmName -PassThru -ActivityName 'post-inject-readiness' -ScriptBlock {
        param($d)
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $d 'verify-service.ps1') *>$null
        $LASTEXITCODE
    } -ArgumentList $dest)
    if ($svcRc -eq 0 -or (Get-Date) -ge $deadline) { break }
    Start-Sleep -Seconds 10
}
if ($svcRc -ne 0) {
    throw "[Invoke-Scenario] $VmName did not return to a serving state after inject $Id (verify-service.ps1 rc=$svcRc)"
}
Write-Host "[Invoke-Scenario] $VmName is serving again after inject $Id"

Write-Host ""
Write-Host "========================================================================"
Write-Host " Scenario $Id staged and injected on $VmName."
Write-Host " Agent works over the SSH bridge (port 22). threat.md is in $dest."
Write-Host " Score with:  lab\Test-ScenarioGates.ps1 -Id $Id"
Write-Host "========================================================================"
