#Requires -RunAsAdministrator
<#
.SYNOPSIS
Defines and installs the SysRepairBench AD lab on Hyper-V.

.DESCRIPTION
AutomatedLab owns VM creation, domain creation, DC promotion, domain join and
Enterprise CA installation. Everything after that -- directory seeding, CA
configuration, scenario injection -- belongs to this repo.

attacker01 is NOT defined here. It is built by New-AttackerVM.ps1 with plain
Hyper-V cmdlets and cloud-init, deliberately, so the Linux guest does not
depend on AutomatedLab's thinner Linux support.

PREREQUISITES (run New-LabSwitches.ps1 first, then this):
  1. LabSources folder must exist and hold the Windows Server 2019 ISO.
     Install-Lab exact-matches -OperatingSystem against
     Get-LabAvailableOperatingSystem and throws "could not be found in the
     available operating systems" if the ISO is absent. Step 0 below handles it.
  2. SRB-Lab must already exist with the host addressed at 10.20.30.1.
#>

[CmdletBinding()]
param(
    [string] $LabSourcesPath,
    [switch] $SkipSourcesCheck
)

$ErrorActionPreference = 'Stop'

$labName    = 'SysRepairBench'
$domainName = 'corp.local'
$adminUser  = 'Administrator'
$adminPass  = 'Password1!'
# Exact string, verified against Get-LabAvailableOperatingSystem on the real
# ISO. Note "Evaluation": the eval media's edition names differ from retail,
# and Install-Lab exact-matches this, so 'Windows Server 2019 Datacenter
# (Desktop Experience)' -- the retail spelling -- throws.
$osName     = 'Windows Server 2019 Datacenter Evaluation (Desktop Experience)'

# --- 0. LabSources preflight ----------------------------------------------
# Missing entirely from the first draft of this plan, and the single most
# common Install-Lab failure.
if (-not $SkipSourcesCheck) {
    if (-not $LabSourcesPath) { $LabSourcesPath = 'C:\LabSources' }

    # The skeleton is created BEFORE AutomatedLab is imported, not after.
    # Import-Module AutomatedLab resolves its LabSources location during
    # import and dies with "Cannot bind argument to parameter 'Path' because
    # it is null" when the folder does not exist -- so any preflight that
    # calls Get-LabSourcesLocation or New-LabSourcesFolder to create it can
    # never run. Verified on a clean host.
    foreach ($d in 'ISOs', 'OSUpdates', 'PostInstallationActivities', 'Tools',
                   'SoftwarePackages', 'CustomRoles', 'LabScripts') {
        $p = Join-Path $LabSourcesPath $d
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }

    Import-Module AutomatedLab -ErrorAction Stop

    $isoDir = Join-Path $LabSourcesPath 'ISOs'
    if (-not (Test-Path $isoDir) -or -not (Get-ChildItem $isoDir -Filter '*.iso' -ErrorAction SilentlyContinue)) {
        throw @"
[lab] No ISOs in $isoDir.

Place the Windows Server 2019 evaluation ISO there, then re-run. Its SHA256
must match the value recorded in lab/IMAGES.md -- verify with:

    . .\lab\Test-ImageChecksums.ps1
    Test-ImageChecksums -ManifestPath .\lab\IMAGES.md -ImageDir '$isoDir'
"@
    }

    $available = Get-LabAvailableOperatingSystem -Path $isoDir |
                 Select-Object -ExpandProperty OperatingSystemName -Unique
    if ($available -notcontains $osName) {
        throw @"
[lab] '$osName' is not among the available operating systems.

Install-Lab exact-matches this string. What the ISO actually offers:
$($available | ForEach-Object { "  - $_" } | Out-String)
Update `$osName in this script to one of the above.
"@
    }
    Write-Host "[lab] LabSources OK: $LabSourcesPath"
}

# --- 0b. base-image drive-letter guard -------------------------------------
# Any mount of the base image -- a repair, or even a read-only inspection --
# can leave a drive-letter assignment persisted in its partition table.
# AutomatedLab copies files to "$($drive.DriveLetter)..." on each new VM's
# disk; with more than one lettered partition that yields an array which
# stringifies to e.g. "S F", and Install-Lab dies with:
#
#   Copy-Item : Cannot find drive. A drive with the name 'S F' does not exist.
#
# Removal is not reliably persisted from a read-only mount, so rather than
# trusting each helper to clean up after itself, strip unconditionally here.
$repairModule = Join-Path $PSScriptRoot 'Repair-LabBaseImage.ps1'
if (Test-Path $repairModule) {
    . $repairModule
    $vmRoot = 'E:\AutomatedLab-VMs'
    if (Test-Path $vmRoot) {
        Write-Host '[lab] stripping any persisted drive letters from base images'
        Clear-LabBaseImageDriveLetters -VMPath $vmRoot
    }
}

# --- 1. lab definition -----------------------------------------------------
New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV

Add-LabDomainDefinition -Name $domainName -AdminUser $adminUser -AdminPassword $adminPass
Set-LabInstallationCredential -Username $adminUser -Password $adminPass

# Default switch type for Add-LabVirtualNetworkDefinition is Internal, which
# matches what New-LabSwitches.ps1 created. AutomatedLab detects the existing
# switch and reuses it.
Add-LabVirtualNetworkDefinition -Name 'SRB-Lab' -AddressSpace 10.20.30.0/24

$common = @{
    OperatingSystem = $osName
    Network         = 'SRB-Lab'
    DomainName      = $domainName
}

# MEMORY: -Memory alone yields STATIC memory. Supplying -MinMemory or
# -MaxMemory is exactly what switches AutomatedLab to Dynamic Memory, so the
# DC and attacker deliberately pass -Memory only. AD's ESE database sizes its
# cache at boot; ballooning a domain controller produces nondeterministic
# directory performance.
Add-LabMachineDefinition -Name 'corp-dc01' @common `
    -IpAddress 10.20.30.5 `
    -Roles RootDC `
    -Memory 3GB

# CA: dynamic memory is acceptable, so Min/Max are supplied here on purpose.
# CACommonName is PINNED: scenarios 07-10 pass 'corp-ca01-CA' to
# `certipy-ad -ca`, and a CA's common name cannot be changed after
# installation. Letting AutomatedLab pick a default would require a full CA
# rebuild to correct.
$caRole = Get-LabMachineRoleDefinition -Role CaRoot -Properties @{
    CACommonName = 'corp-ca01-CA'
    KeyLength    = '2048'
    ValidityPeriod      = 'Years'
    ValidityPeriodUnits = '10'
}

Add-LabMachineDefinition -Name 'corp-ca01' @common `
    -IpAddress 10.20.30.6 `
    -Roles $caRole `
    -Memory 2GB -MinMemory 1GB -MaxMemory 2GB

# Member workstation. Enables the behavioural PoCs for S13, S15, S17 and S19,
# which currently cannot poison, relay to, coerce or manage anything because
# the lab has no domain member.
Add-LabMachineDefinition -Name 'corp-ws01' @common `
    -IpAddress 10.20.30.20 `
    -Memory 2GB -MinMemory 1GB -MaxMemory 2GB

Install-Lab

# -Detailed was removed from Show-LabDeploymentSummary upstream; -Summary is
# the current parameter.
Show-LabDeploymentSummary -Summary

Write-Host ''
Write-Host '[lab] Install-Lab complete. Next:'
Write-Host '      . .\lab\Protect-ParentDisk.ps1; Set-LabVMHardening'
Write-Host '      (hardening MUST run before any baseline is captured)'
