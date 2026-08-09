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

# NOT registered with Add-LabIsoImageDefinition. New-LabDefinition auto-adds
# every ISO under LabSources itself (AutomatedLabDefinition.psm1:3020), and
# calling Add-LabIsoImageDefinition by hand is what BROKE this lab for weeks --
# see the cache guard immediately below. The check above is a PRECONDITION, so a
# missing ISO fails here with a sentence an operator can act on rather than deep
# inside Install-Lab. ad-vm registers nothing and builds cleanly; this matches it.

# --- 0a. GUARD: purge a poisoned LocalIsoImages cache ---
#
# ROOT CAUSE of "There isn't a single operating system ISO available in the lab",
# MEASURED, not theorised. Install-Lab -> New-LabBaseImages
# (AutomatedLabCore.psm1:14403) tests $lab.Sources.AvailableOperatingSystems.
# That property has no backing field: decompiling its getter from AutomatedLab.dll
# gives isos.Cast<IsoImage>().SelectMany(i => i.OperatingSystems).ToList(). So it
# is 0 whenever every ISO in the lab carries an EMPTY OperatingSystems list --
# which is exactly why .ISOs looked healthy (2 correct paths) while the check
# still failed.
#
# The empty lists came from the persistent cache
# HKCU:\Software\AutomatedLab\Cache\LocalIsoImages. Measured content before the
# fix -- note the hand-assigned name, auto-add uses [guid]::NewGuid():
#     <IsoImage><Name>Server2019</Name>
#       <Path>...SERVER_EVAL_x64FRE_en-us.iso</Path>
#       <Size>5652088832</Size><OperatingSystems /></IsoImage>
#
# How it got poisoned: Add-LabIsoImageDefinition guards its "mount the ISO and
# read the editions" block with (AutomatedLabDefinition.psm1:525)
#     if (-not $script:lab.DefaultVirtualizationEngine -eq 'Azure')
# PowerShell parses that as ((-not $engine) -eq 'Azure'). New-LabDefinition's own
# auto-add runs while DefaultVirtualizationEngine is still unset (it is assigned
# at :3026, AFTER the :3020 auto-add), so -not '' -> $true -eq 'Azure' -> $true
# and the editions ARE read. A MANUAL Add-LabIsoImageDefinition after
# New-LabDefinition sees engine 'HyperV', so -not 'HyperV' -> $false -eq 'Azure'
# -> $false, the block is skipped, $isOperatingSystem stays $null, and the ISO is
# written to the registry cache with zero editions (:554, :578). Thereafter every
# New-LabDefinition matches that entry by Path+Size (:513) and reuses the empty
# object instead of re-reading the media -- so deleting the manual call, as an
# earlier revision of this script did, does NOT recover. The poison outlives it.
#
# A/B PROOF on this host, one variable changed, same probe script:
#   before purge: ISOs.Count=2  AvailableOperatingSystems.Count=0  (Server2019 OSes=0)
#   after  purge: ISOs.Count=2  AvailableOperatingSystems.Count=4  (GUID name, OSes=4)
# 4 matches meta4/ad-vm's already-built SysRepairBench lab exactly.
#
# This guard is kept rather than treated as a one-off cleanup because the failure
# is completely opaque -- AutomatedLab reports a missing ISO when the ISO is
# present and readable -- and any future Add-LabIsoImageDefinition re-poisons it.
$isoCacheKey = 'HKCU:\Software\AutomatedLab\Cache'
$poisoned = $false
try {
    $isoCacheXml = Get-ItemPropertyValue -Path $isoCacheKey -Name 'LocalIsoImages' -ErrorAction Stop
    $isoCacheDoc = [xml] $isoCacheXml
    foreach ($entry in $isoCacheDoc.ListXmlStoreOfIsoImage.IsoImage) {
        if ($entry.Path -eq $server2019Iso.FullName -and -not $entry.OperatingSystems.HasChildNodes) {
            $poisoned = $true
        }
    }
} catch {
    # No cache value yet (fresh host) -- nothing to purge, New-LabDefinition builds it.
}
if ($poisoned) {
    Write-Host "[lab] LocalIsoImages cache lists $($server2019Iso.Name) with ZERO editions; purging so New-LabDefinition re-reads the media."
    Remove-ItemProperty -Path $isoCacheKey -Name 'LocalIsoImages' -ErrorAction Stop
}

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
# This is edition/media resolution only. It was NEVER the cause of the
# "There isn't a single operating system ISO available in the lab" failure --
# passing the object rather than the name does not change that check either way.
# That failure is the poisoned LocalIsoImages cache handled in step 0a above.
#
# Note this reads the LocalOperatingSystems cache, a DIFFERENT registry value
# from LocalIsoImages. It returned all editions correctly the entire time the
# lab was unbuildable, which is precisely what made the failure so misleading.
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

# --- post-install: OpenSSH.Server Feature-on-Demand needs the internet ONCE ---
#
# baseline.ps1 step 1 calls Add-WindowsCapability for OpenSSH.Server. That
# capability's payload is NOT on the Server 2019 media -- DISM fetches it from
# Windows Update -- and this lab's switch is Internal by design, so the guest has
# no route out. MEASURED failure modes, both on this host:
#
#   via Invoke-LabCommand (WinRM, network logon):  HRESULT 0x80070005 "Access is
#       denied."  <- misleading; it is the second hop that has no credentials
#   via PowerShell Direct (local logon):           HRESULT 0x8024402C
#       WU_E_PT_WINHTTP_NAME_NOT_RESOLVED  <- the real story: no DNS, no internet
#
# The 0x80070005 form is what Install-Lab surfaced and it names nothing useful,
# which is why this is worth spelling out.
#
# Fix mirrors hivestorm/scenario-13's Install-Hs13OpenSshServer: attach the
# existing EXTERNAL build switch for the duration of the fetch, then detach. The
# lab goes back to being isolated -- an SMB/RDP scenario whose host can reach the
# internet is a different scenario, and leaving the adapter on would silently
# change what is graded.
#
# This runs BEFORE the baseline snapshot on purpose, so sshd is inside the
# snapshot and Restore-LabBaseline never needs the internet again.
#
# Uses PowerShell Direct rather than Invoke-LabCommand: DISM online servicing
# under a WinRM network logon is what produced the 0x80070005 above.
$BuildSwitch = 'SRB-Build'
$labCred = New-Object System.Management.Automation.PSCredential(
    $AdminUser, (ConvertTo-SecureString $AdminPass -AsPlainText -Force))

# .ToString() ON THE GUEST. DISM's State is an enum and PowerShell Direct
# serialises it to its numeric value, so comparing the result to 'Installed'
# here would compare '4' -eq 'Installed' -> $false and report a good install as
# a failure. (Same trap documented in hivestorm/.../Hs13Ops.ps1.)
$sshState = Invoke-Command -VMName $VmName -Credential $labCred -ScriptBlock {
    (Get-WindowsCapability -Online -Name 'OpenSSH.Server*').State.ToString()
}

if ($sshState -eq 'Installed') {
    Write-Host '[lab] OpenSSH.Server already present'
}
else {
    if (-not (Get-VMSwitch -Name $BuildSwitch -ErrorAction SilentlyContinue)) {
        throw ("SysRepairLab: external switch '$BuildSwitch' not found. It is needed ONCE to " +
               'fetch the OpenSSH.Server Feature-on-Demand; the lab switch is Internal and ' +
               'cannot reach Windows Update. Create an external switch or pre-install the capability.')
    }

    $adapterAdded = $false
    try {
        if (-not (Get-VMNetworkAdapter -VMName $VmName | Where-Object SwitchName -eq $BuildSwitch)) {
            Add-VMNetworkAdapter -VMName $VmName -SwitchName $BuildSwitch -Name 'meta3-build'
            $adapterAdded = $true
            Write-Host "[lab] attached '$BuildSwitch' temporarily for the OpenSSH FoD download"
        }

        # Waiting for a default route is NOT sufficient. The failure is
        # 0x8024402C, name-not-resolved, so the gate is DNS + a real TCP
        # connection. (This guest has no default route at all until the build
        # adapter gets DHCP -- measured: Get-NetRoute 0.0.0.0/0 returned nothing.)
        $deadline = (Get-Date).AddSeconds(180)
        $online = $false
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 6
            $online = Invoke-Command -VMName $VmName -Credential $labCred -ScriptBlock {
                try {
                    $null = Resolve-DnsName -Name 'go.microsoft.com' -Type A -ErrorAction Stop
                    Test-NetConnection -ComputerName 'go.microsoft.com' -Port 443 `
                        -InformationLevel Quiet -WarningAction SilentlyContinue
                } catch { $false }
            }
            if ($online) { break }
        }
        if (-not $online) {
            throw "SysRepairLab: $VmName never reached the internet via '$BuildSwitch'; cannot fetch the OpenSSH FoD."
        }

        Write-Host '[lab] installing OpenSSH.Server (Feature on Demand)...'
        $sshState = Invoke-Command -VMName $VmName -Credential $labCred -ScriptBlock {
            $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' |
                     Where-Object State -ne 'Installed' | Select-Object -First 1
            if ($cap) { Add-WindowsCapability -Online -Name $cap.Name | Out-Null }
            (Get-WindowsCapability -Online -Name 'OpenSSH.Server*').State.ToString()
        }
        if ($sshState -ne 'Installed') {
            throw "SysRepairLab: OpenSSH.Server state is '$sshState' after install."
        }
        Write-Host '[lab] OpenSSH.Server installed'
    }
    finally {
        if ($adapterAdded) {
            Get-VMNetworkAdapter -VMName $VmName |
                Where-Object SwitchName -eq $BuildSwitch |
                Remove-VMNetworkAdapter
            Write-Host "[lab] detached '$BuildSwitch' -- lab is isolated again"
        }
    }
}

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

# --- settle the servicing stack BEFORE anyone snapshots this VM ---
#
# baseline.ps1 runs `Disable-WindowsOptionalFeature -FeatureName SMB1Protocol
# -NoRestart`, which leaves CBS in a reboot-pending state. Snapshotting there
# bakes the pending reboot into the 'baseline' checkpoint that every scenario
# run restores, and MEASURED consequences follow:
#
#   Get-WindowsOptionalFeature SMB1Protocol -> State  : Enabled   (after inject)
#   Get-Service srv                         -> exists : False
#   HKLM:\...\Component Based Servicing\RebootPending  : True
#   Set-SmbServerConfiguration -EnableSMB1Protocol $true
#                                           -> "The specified service does not exist."
#
# i.e. scenario-10's inject could not make the box vulnerable at all, because
# the SMB1 driver is only registered on reboot. Rebooting here and letting
# Wait-LabVM confirm the VM is back makes the snapshot a settled state.
Write-Host '[lab] rebooting to settle the servicing stack before the baseline snapshot'
Restart-LabVM -ComputerName $VmName -Wait
Wait-LabVM -ComputerName $VmName -TimeoutInMinutes 15

Show-LabDeploymentSummary

Write-Host "[SysRepairLab] lab '$LabName' built. Next: lab\Save-LabBaseline.ps1 to snapshot the hardened baseline."
