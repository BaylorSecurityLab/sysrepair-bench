#Requires -RunAsAdministrator

Import-Module "$PSScriptRoot/LabReadiness.psm1" -Force
. "$PSScriptRoot/Start-LabOrdered.ps1"
. "$PSScriptRoot/Save-LabBaseline.ps1"

function Restore-LabBaseline {
    <#
    .SYNOPSIS
    Restores all four machines to `baseline` and brings them up in order.

    .DESCRIPTION
    ALL FOUR MACHINES ARE RESTORED TOGETHER, AND THAT IS LOAD-BEARING.

    Restoring a domain controller from a hypervisor checkpoint is normally
    dangerous -- USN rollback and DFSR divergence. It is safe here for two
    specific reasons, both of which are invariants rather than luck:

      1. This is a SINGLE-DC forest. USN rollback and DFSR divergence both
         require a replication partner, so neither is structurally possible.
      2. Every machine is restored from the SAME INSTANT, so member secure
         channels stay consistent with the DC's view of them.

    Adding a second DC, or restoring one machine independently, breaks both
    invariants immediately. The -VMName parameter therefore validates that the
    full set is being restored; restoring a subset is refused rather than
    silently permitted.
    #>
    [CmdletBinding()]
    param(
        [string[]] $VMName = @('corp-dc01', 'corp-ca01', 'corp-ws01', 'attacker01'),

        # Non-DC machines to gate on after restore. Narrow during bring-up,
        # before attacker01 exists.
        [ValidateSet('ca', 'ws', 'attacker')]
        [string[]] $Members = @('ca', 'ws', 'attacker'),

        # Escape hatch for deliberate single-machine work. Requires the caller
        # to state that they accept the divergence risk.
        [switch] $AllowPartialRestore
    )

    $full = @('corp-dc01', 'corp-ca01', 'corp-ws01', 'attacker01')
    $diff = $full | Where-Object { $_ -notin $VMName }

    if ($diff -and -not $AllowPartialRestore) {
        throw @"
Restore-LabBaseline: refusing a partial restore (missing: $($diff -join ', ')).

All machines must be restored from the same instant or member secure channels
diverge from the DC's view of them. Pass -AllowPartialRestore only if you
understand and accept that.
"@
    }

    foreach ($vm in $VMName) {
        if (-not (Get-VMSnapshot -VMName $vm -Name 'baseline' -ErrorAction SilentlyContinue)) {
            throw "Restore-LabBaseline: '$vm' has no baseline checkpoint. Run Save-LabBaseline first."
        }
    }

    foreach ($vm in $VMName) { Stop-LabVMCold -VMName $vm }

    foreach ($vm in $VMName) {
        Restore-VMSnapshot -VMName $vm -Name 'baseline' -Confirm:$false
        Write-Host "[restore] $vm restored to baseline"
    }

    foreach ($vm in $VMName) { Wait-VMSnapshotMerge -VMName $vm }

    return Start-LabOrdered -Members $Members
}
