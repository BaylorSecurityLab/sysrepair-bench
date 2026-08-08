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
    # Empty = RESOLVE FROM THE MEDIA (see below). Pass a name only to override.
    [string] $OsName     = '',
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

# --- 0. PREFLIGHT, all of it BEFORE New-LabDefinition ---
#
# Ordering is load-bearing and was the last thing keeping this lab from
# building. meta4/ad-vm resolves media and edition in a preflight and only then
# defines the lab; this script did it in the middle of the definition, and
# calling Get-LabAvailableOperatingSystem after New-LabDefinition left
# Install-Lab insisting
#     There isn't a single operating system ISO available in the lab.
# even though the edition had just been resolved from that very ISO. Matching
# ad-vm's order fixes it.
#
# $LabSourcesPath is also resolved EXPLICITLY here. The script previously read
# a bare $labSources that it never assigned -- it happened to work only because
# the AutomatedLab module exports a global of that name, which is not something
# to depend on.
$LabSourcesPath = Get-LabSourcesLocation
$isoDir = Join-Path $LabSourcesPath 'ISOs'
$server2019Iso =
    Get-ChildItem -Path $isoDir -Filter '*.iso' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'SERVER_EVAL' -or $_.Name -match 'WindowsServer2019' -or $_.Name -match '^17763\.' } |
    Sort-Object Length -Descending | Select-Object -First 1

if (-not $server2019Iso) {
    throw ("SysRepairLab: no Windows Server 2019 evaluation ISO found in $isoDir. " +
           'Download the Server 2019 Eval ISO there; see lab/RUNBOOK.md.')
}
Write-Host "[lab] Server 2019 media: $($server2019Iso.Name)"

# NOT registered with Add-LabIsoImageDefinition. New-LabDefinition already
# auto-adds every ISO under LabSources -- the build log shows it doing so -- and
# registering the same file a second time left Install-Lab reporting
#     There isn't a single operating system ISO available in the lab.
# The check above is a PRECONDITION, so a missing ISO fails here with a sentence
# an operator can act on rather than deep inside Install-Lab. ad-vm registers
# nothing and builds cleanly; this now matches it.

# --- resolve the OS edition FROM THE MEDIA, not from a hardcoded string ---
#
# The script asked for 'Windows Server 2019 Datacenter (Desktop Experience)'
# and Install-Lab refused: the evaluation media this lab uses names its editions
# '... Datacenter EVALUATION (Desktop Experience)'. Hardcoding an edition string
# is the same mistake as hardcoding the ISO filename, one layer down -- it
# depends on which media the operator happened to download.
#
# Desktop Experience is REQUIRED, not a preference: scenario-12 grades a live
# RDP/TermService negotiation, and Server Core does not run TermService.
# The OS OBJECT is kept rather than just its name. Add-LabMachineDefinition
# accepts either; the object carries the IsoPath binding, which is strictly more
# information and costs nothing.
#
# NOT a fix for the outstanding build failure -- see BLOCKER in RUNBOOK.md. That
# is Install-Lab throwing "There isn't a single operating system ISO available
# in the lab" at base-image creation, where it tests
# $lab.Sources.AvailableOperatingSystems. Passing the object does not change it.
$osObjects = Get-LabAvailableOperatingSystem -Path $isoDir

$osObject = $osObjects |
    Where-Object { $_.OperatingSystemName -match 'Server 2019' -and
                   $_.OperatingSystemName -match 'Desktop Experience' } |
    Sort-Object { if ($_.OperatingSystemName -match 'Datacenter') { 0 } else { 1 } } |
    Select-Object -First 1

if ($OsName) {
    # Explicit override still wins, but must exist in the media.
    $osObject = $osObjects | Where-Object OperatingSystemName -eq $OsName | Select-Object -First 1
    if (-not $osObject) {
        throw ("SysRepairLab: requested edition '$OsName' is not in the media. Available: " +
               (($osObjects.OperatingSystemName | Sort-Object -Unique) -join '; '))
    }
}

if (-not $osObject) {
    throw ("SysRepairLab: no Server 2019 'Desktop Experience' edition found in the media. " +
           "Desktop Experience is required -- Server Core has no TermService, which " +
           "scenario-12 grades. Available: " +
           (($osObjects.OperatingSystemName | Sort-Object -Unique) -join '; '))
}
$OsName = $osObject.OperatingSystemName
Write-Host "[lab] OS edition: $OsName"
Write-Host "[lab] from media: $($osObject.IsoPath)"

# --- 1. lab shell: Hyper-V engine, one internal switch ---
# Defined only now that media and edition are known good.
New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV

Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace $AddressSpace

Set-LabInstallationCredential -Username $AdminUser -Password $AdminPass

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
    -OperatingSystem $osObject `
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
