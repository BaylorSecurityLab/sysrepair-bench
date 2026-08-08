#Requires -RunAsAdministrator
<#
.SYNOPSIS
Restore the meta3/windows-vm host to its 'baseline' checkpoint.

.DESCRIPTION
Idempotent reset before each scenario inject (mirrors meta4/ad-vm's reset.sh).
Restores the AutomatedLab/Hyper-V checkpoint and waits for the VM to be
reachable again (WinRM/PowerShell Direct) before returning.
#>
[CmdletBinding()]
param(
    [string] $LabName      = 'SysRepairMeta3',
    [string] $VmName       = 'META3WIN',
    [string] $SnapshotName = 'baseline'
)

$ErrorActionPreference = 'Stop'
Import-Module AutomatedLab -ErrorAction Stop

Import-Lab -Name $LabName -NoValidation

# Filter on SnapshotName, NOT Name. Get-LabVMSnapshot returns
# [AutomatedLab.Snapshot] objects whose only properties are SnapshotName,
# CreationTime and ComputerName -- there is no Name property, so
# `Where-Object Name -eq` silently matched nothing and this script threw
# "no 'baseline' checkpoint on META3WIN" against a checkpoint that provably
# existed (Get-VMSnapshot showed it). MEASURED, not inferred:
#     Get-LabVMSnapshot -ComputerName META3WIN | Format-List *
#     SnapshotName : baseline
#     CreationTime : 8/8/2026 9:32:48 AM
#     ComputerName : META3WIN
# Every scenario run starts by restoring the baseline, so this made the whole
# per-scenario harness unusable.
$snap = Get-LabVMSnapshot -ComputerName $VmName -ErrorAction SilentlyContinue |
    Where-Object SnapshotName -eq $SnapshotName
if (-not $snap) {
    throw "[Restore-LabBaseline] no '$SnapshotName' checkpoint on $VmName. Run Save-LabBaseline.ps1 first."
}

Write-Host "[Restore-LabBaseline] restoring '$SnapshotName' on $VmName"
Restore-LabVMSnapshot -ComputerName $VmName -SnapshotName $SnapshotName

# Ensure the VM is up and responsive before handing back.
Start-LabVM -ComputerName $VmName -Wait -ErrorAction SilentlyContinue
Wait-LabVM -ComputerName $VmName -TimeoutInMinutes 10

Write-Host "[Restore-LabBaseline] $VmName restored and reachable"
