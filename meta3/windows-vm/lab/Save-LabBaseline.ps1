#Requires -RunAsAdministrator
<#
.SYNOPSIS
Snapshot the hardened baseline of the meta3/windows-vm host.

.DESCRIPTION
Uses AutomatedLab's Checkpoint-LabVM (Hyper-V checkpoints under the hood) to
capture a 'baseline' checkpoint after provision/baseline.ps1 has run. Every
scenario run restores this checkpoint first, so injects always start from the
same hardened state (SMB1 off, signing required, RDP NLA on).

Run ONCE after SysRepairLab.ps1 completes; re-run only after an intentional
baseline change.
#>
[CmdletBinding()]
param(
    [string] $LabName        = 'SysRepairMeta3',
    [string] $VmName         = 'META3WIN',
    [string] $SnapshotName   = 'baseline'
)

$ErrorActionPreference = 'Stop'
Import-Module AutomatedLab -ErrorAction Stop

Import-Lab -Name $LabName -NoValidation

# Refresh: drop any stale baseline before recapturing.
$existing = Get-LabVMSnapshot -ComputerName $VmName -ErrorAction SilentlyContinue |
    Where-Object Name -eq $SnapshotName
if ($existing) {
    Write-Host "[Save-LabBaseline] removing existing '$SnapshotName' checkpoint"
    Remove-LabVMSnapshot -ComputerName $VmName -SnapshotName $SnapshotName
}

Write-Host "[Save-LabBaseline] capturing '$SnapshotName' checkpoint on $VmName"
Checkpoint-LabVM -ComputerName $VmName -SnapshotName $SnapshotName

Write-Host "[Save-LabBaseline] done"
