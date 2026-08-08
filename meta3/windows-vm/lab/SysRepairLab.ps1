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
    # [int64], not [int]: 3072MB is 3,221,225,472 bytes and Int32 tops out at
    # 2,147,483,647, so the parameter transformation threw before the script ran
    # a single line -- "Cannot convert value 3221225472 to type System.Int32".
    # Any lab over 2GB was unbuildable, which nothing noticed while this suite
    # sat authored-but-never-deployed.
    [int64]  $Memory     = 3072MB,
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
#
# Resolved by DISCOVERY, not by a fixed filename. Microsoft ships the evaluation
# media under its build name -- 17763.3650.221105-1748.rs5_release_svc_refresh_
# SERVER_EVAL_x64FRE_en-us.iso -- and the previous hardcoded
# "WindowsServer2019Eval.iso" matched nothing on this host. Because the call
# carried -ErrorAction SilentlyContinue it failed silently, leaving the outcome
# to AutomatedLab's own auto-discovery and turning a missing ISO into a
# confusing failure much later in the build. ad-vm never registers an ISO by
# name at all, which is why it builds cleanly.
$isoDir = Join-Path $labSources 'ISOs'
$server2019Iso =
    Get-ChildItem -Path $isoDir -Filter '*.iso' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'SERVER_EVAL' -or $_.Name -match 'WindowsServer2019' -or $_.Name -match '^17763\.' } |
    Sort-Object Length -Descending | Select-Object -First 1

if (-not $server2019Iso) {
    throw ("SysRepairLab: no Windows Server 2019 evaluation ISO found in $isoDir. " +
           'Download the Server 2019 Eval ISO there; see lab/RUNBOOK.md.')
}
Write-Host "[lab] Server 2019 media: $($server2019Iso.Name)"
Add-LabIsoImageDefinition -Name Server2019 -Path $server2019Iso.FullName

# --- the one standalone member server (workgroup; no DC) ---
$netParams = @{
    InterfaceName = 'Ethernet'
    IpAddress     = $VmIpAddress
    PrefixLength  = 24
    Gateway       = '192.168.30.1'
}
# -DomainName is OMITTED, not passed empty. This machine is a WORKGROUP member
# by design (the whole point of the suite: a standalone SMB/RDP host, no DC), and
# AutomatedLab treats the absence of -DomainName as exactly that. Passing '' does
# not mean "no domain" -- it fails ValidatePattern before Install-Lab is reached:
#     Cannot validate argument on parameter 'DomainName'. The argument ""
#     does not match the ... pattern.
# so the lab could never be built.
Add-LabMachineDefinition -Name $VmName `
    -OperatingSystem $OsName `
    -Memory $Memory `
    -Processors $Cpu `
    -Network $LabName `
    -IpAddress $VmIpAddress `
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
