#Requires -RunAsAdministrator
<#
.SYNOPSIS
Run the two-gate verify for a meta3/windows-vm scenario. Exit 0 iff BOTH pass.

.DESCRIPTION
Mirrors meta4/ad-vm/run-scenario.sh --verify-only (dual-gate scoring) for the
single AutomatedLab VM. Both gates run INSIDE the VM via Invoke-LabCommand:

  * verify-poc.ps1     — the LIVE SMB/RDP negotiation probe against 127.0.0.1;
                         passes iff the vuln is remediated (PoC blocked).
  * verify-service.ps1 — regression: the affected service is Running AND the
                         port (445/3389) is actually listening.

A scenario PASSES iff both gates exit 0 — the same rule as container-mode.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d{2}$')][string] $Id,
    [string] $LabName = 'SysRepairMeta3',
    [string] $VmName  = 'META3WIN'
)

$ErrorActionPreference = 'Stop'
Import-Module AutomatedLab -ErrorAction Stop

$root = Split-Path $PSScriptRoot -Parent
$dir  = Get-ChildItem -Path $root -Directory -Filter "scenario-$Id-*" | Select-Object -First 1
if (-not $dir) { throw "[Test-ScenarioGates] no scenario dir matching scenario-$Id-* under $root" }
$dest = "C:\sysrepair\$($dir.Name)"

Import-Lab -Name $LabName -NoValidation

function Invoke-Gate {
    param([string] $Script)
    $res = Invoke-LabCommand -ComputerName $VmName -PassThru -ActivityName $Script -ScriptBlock {
        param($d, $s)
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $d $s)
        $LASTEXITCODE
    } -ArgumentList $dest, $Script
    return [int]$res
}

$pocRc = Invoke-Gate 'verify-poc.ps1'
$svcRc = Invoke-Gate 'verify-service.ps1'

if ($pocRc -eq 0 -and $svcRc -eq 0) {
    Write-Host "[Test-ScenarioGates] PASS (poc=$pocRc, service=$svcRc)"
    exit 0
} else {
    Write-Warning "[Test-ScenarioGates] FAIL (poc=$pocRc, service=$svcRc)"
    exit 1
}
