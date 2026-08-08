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

# --- two-component summary, for scorer.py ---
#
# Same wire format lib/verifylib.{sh,ps1} and meta4/ad-vm's Invoke-ScenarioVerify
# emit, because scorer.py parses all of them with one function. Without this the
# scorer sees only the exit code and the whole point of the split -- telling
# "closed the vulnerability" apart from "closed it by killing the service" --
# is lost for this suite, even though the two gates measured it.
#
# Exit code 2 from a gate means the probe COULD NOT RUN. That is not a verdict,
# so the component is null rather than false; grading an unmeasurable probe
# either way would be a statement about the harness, not the host. joint is null
# whenever either component is, never true -- a joint claim over an unmeasured
# component is exactly the bug that let "kill the service" score a clean pass
# elsewhere in this benchmark.
function ConvertTo-Component { param([int] $Rc)
    if ($Rc -eq 0) { return 'true' }
    if ($Rc -eq 2) { return 'null' }   # probe could not run
    return 'false'
}

$sec = ConvertTo-Component $pocRc
$reg = ConvertTo-Component $svcRc
$joint =
    if ($sec -eq 'null' -or $reg -eq 'null') { 'null' }
    elseif ($sec -eq 'true' -and $reg -eq 'true') { 'true' }
    else { 'false' }

Write-Output ('{{"sysrepair_summary":true,"security_pass":{0},"regression_pass":{1},"joint_pass":{2},"poc_total":1,"poc_failed":{3},"reg_total":1,"reg_failed":{4},"track":"meta3-windows-vm"}}' -f `
    $sec, $reg, $joint,
    $(if ($sec -eq 'false') { 1 } else { 0 }),
    $(if ($reg -eq 'false') { 1 } else { 0 }))

if ($pocRc -eq 0 -and $svcRc -eq 0) {
    Write-Host "[Test-ScenarioGates] PASS (poc=$pocRc, service=$svcRc)"
    exit 0
} else {
    Write-Warning "[Test-ScenarioGates] FAIL (poc=$pocRc, service=$svcRc)"
    exit 1
}
