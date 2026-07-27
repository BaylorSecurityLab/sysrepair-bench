#Requires -RunAsAdministrator
<#
.SYNOPSIS
AutomatedLab definition for the meta3/windows-vm standalone SMB/RDP host.

.DESCRIPTION
Builds a MINIMAL lab: a single standalone Windows Server 2019 member
(workgroup, no domain controller — SMB and RDP need neither AD nor Kerberos)
that hosts scenarios 10-smbv1, 11-smb-signing and 12-rdp-nla. Each scenario
is injected on a restored baseline (mirrors meta4/ad-vm's one-lab /
per-scenario-inject model), so 445/3389 genuinely listen and the live SMB/RDP
negotiation probes actually reach a running server.

Shared infra reuse (documented in RUNBOOK.md):
  * Hyper-V + AutomatedLab, same host role as meta4/ad-vm.
  * Windows Server 2019 Evaluation ISO in C:\LabSources\ISOs  (same convention
    as ad-vm's LabSources/ISO usage).
  * lab/Repair-LabBaseImage.ps1 is copied verbatim from meta4/ad-vm/lab — the
    empty-ESP base-image repair applies identically to any Server 2019 image on
    a newer Win11 host.

.NOTES
Pure authoring artefact. Do NOT run on a RAM-constrained host or while another
session owns Hyper-V. See lab/RUNBOOK.md for the deploy+validate sequence.
#>
[CmdletBinding()]
param(
    [string] $LabName    = 'SysRepairMeta3',
    [string] $VmName     = 'META3WIN',
    [string] $AddressSpace = '192.168.30.0/24',
    [string] $VmIpAddress  = '192.168.30.10',
    [string] $OsName     = 'Windows Server 2019 Datacenter (Desktop Experience)',
    [int]    $Memory     = 3072MB,
    [int]    $Cpu        = 2,
    [string] $AdminUser  = 'Administrator',
    [string] $AdminPass  = 'Somepass1!'
)

$ErrorActionPreference = 'Stop'

Import-Module AutomatedLab -ErrorAction Stop

# --- lab shell: Hyper-V engine, one internal switch ---
New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV

Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace $AddressSpace

Set-LabInstallationCredential -Username $AdminUser -Password $AdminPass

# ISO convention shared with meta4/ad-vm (C:\LabSources\ISOs).
Add-LabIsoImageDefinition -Name Server2019 -Path "$labSources\ISOs\WindowsServer2019Eval.iso" -ErrorAction SilentlyContinue

# --- the one standalone member server (workgroup; no DC) ---
$netParams = @{
    InterfaceName = 'Ethernet'
    IpAddress     = $VmIpAddress
    PrefixLength  = 24
    Gateway       = '192.168.30.1'
}
Add-LabMachineDefinition -Name $VmName `
    -OperatingSystem $OsName `
    -Memory $Memory `
    -Processors $Cpu `
    -Network $LabName `
    -IpAddress $VmIpAddress `
    -DomainName '' `
    -Notes @{ Role = 'meta3-windows-vm standalone SMB/RDP host' }

# --- build it ---
Install-Lab

# --- post-install: run the hardened baseline provisioner inside the VM ---
# CopyItem stages provision/baseline.ps1, then Invoke-LabCommand runs it. Supply
# the bridge pubkey at deploy time (see RUNBOOK) so the scorer's SSH bridge works.
$provision = Join-Path $PSScriptRoot '..\provision\baseline.ps1'
$bridgePub = Join-Path $PSScriptRoot '..\build\bridge_key.pub'
$pubContent = if (Test-Path $bridgePub) { Get-Content $bridgePub -Raw } else { '' }

Copy-LabFileItem -Path $provision -ComputerName $VmName -DestinationFolderPath 'C:\sysrepair'
Invoke-LabCommand -ComputerName $VmName -ActivityName 'baseline-provision' `
    -ScriptBlock {
        param($pub)
        & 'C:\sysrepair\baseline.ps1' -BridgePubKey $pub
    } -ArgumentList $pubContent

Show-LabDeploymentSummary

Write-Host "[SysRepairLab] lab '$LabName' built. Next: lab\Save-LabBaseline.ps1 to snapshot the hardened baseline."
