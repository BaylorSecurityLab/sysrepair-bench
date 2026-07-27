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

$snap = Get-LabVMSnapshot -ComputerName $VmName -ErrorAction SilentlyContinue |
    Where-Object Name -eq $SnapshotName
if (-not $snap) {
    throw "[Restore-LabBaseline] no '$SnapshotName' checkpoint on $VmName. Run Save-LabBaseline.ps1 first."
}

Write-Host "[Restore-LabBaseline] restoring '$SnapshotName' on $VmName"
Restore-LabVMSnapshot -ComputerName $VmName -SnapshotName $SnapshotName

# Ensure the VM is up and responsive before handing back.
Start-LabVM -ComputerName $VmName -Wait -ErrorAction SilentlyContinue
Wait-LabVM -ComputerName $VmName -TimeoutInMinutes 10

Write-Host "[Restore-LabBaseline] $VmName restored and reachable"
