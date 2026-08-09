#Requires -RunAsAdministrator
<#
.SYNOPSIS
Run the two-gate verify for a meta3/windows-vm scenario. Exit 0 iff BOTH pass.

.DESCRIPTION
Mirrors meta4/ad-vm/run-scenario.sh --verify-only (dual-gate scoring) for the
single AutomatedLab VM. Both gates run INSIDE the VM via Invoke-LabCommand:

  * verify-poc.ps1     -- the LIVE SMB/RDP negotiation probe against 127.0.0.1;
                         passes iff the vuln is remediated (PoC blocked).
  * verify-service.ps1 -- regression: the affected service is Running AND the
                         port (445/3389) is actually listening.

A scenario PASSES iff both gates exit 0 -- the same rule as container-mode.
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

# Run one gate inside the VM and return ONLY its exit code.
#
# The gate scripts are launched as a child powershell.exe, so every line they
# print lands in this scriptblock's pipeline as a string. The previous version
# emitted $LASTEXITCODE after that and cast the lot with [int]$res, which threw
#     Cannot convert the "System.Object[]" value ... to type "System.Int32"
# the moment a gate printed anything at all -- so the summary record was never
# emitted and the suite could not be scored. The diagnostics are therefore
# separated from the verdict: gate output is relayed to the host with
# Write-Host, and the exit code comes back on a tagged object that cannot be
# confused with a line of text. That tagged object doubles as the "this ran"
# signal AutomatedLab's retry loop looks for (see lab/Invoke-Scenario.ps1).
function Invoke-Gate {
    param([string] $Script)
    $res = Invoke-LabCommand -ComputerName $VmName -PassThru -ActivityName $Script -ScriptBlock {
        param($d, $s)
        # A FAILING gate is the normal case here, and gates report failure with
        # Write-Error. Under the Stop preference this scriptblock inherits, the
        # child's stderr comes back as a terminating NativeCommandError, so
        # Invoke-LabCommand threw and Test-ScenarioGates.ps1 died BEFORE writing
        # the sysrepair_summary record -- the record went missing precisely when
        # a gate had something to report. MEASURED on scenario 11, whose
        # verify-poc.ps1 writes to stderr: the run ended in NativeCommandError
        # with no summary line at all. Both streams are captured instead and
        # relayed as diagnostics; the exit code is the only verdict.
        $ErrorActionPreference = 'Continue'
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $d $s) 2>&1
        $rc  = $LASTEXITCODE
        foreach ($line in $out) { Write-Host "    $line" }
        [pscustomobject]@{ SysRepairGateExitCode = $rc }
    } -ArgumentList $dest, $Script

    $marker = @($res) |
        Where-Object { $null -ne $_ -and $_.PSObject.Properties.Name -contains 'SysRepairGateExitCode' } |
        Select-Object -Last 1
    if (-not $marker) {
        throw "[Test-ScenarioGates] $Script produced no exit code on $VmName - the gate did not run"
    }
    return [int]$marker.SysRepairGateExitCode
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
