# hivestorm/scenario-13-ad-dc-win2019/lab/Hs13Lab.ps1
#
# Builds the S13 domain controller on Hyper-V via AutomatedLab, replacing the
# Vagrant/VirtualBox path.
#
# WHY THIS REPLACES dc-bootstrap.ps1 ENTIRELY.
#
# The Vagrant path shipped a three-phase bootstrap that ran Install-ADDSForest
# itself, from a scheduled task, because promotion destroys the local SAM
# mid-session and kills the WinRM connection the provisioner is using. That is
# a real problem and the old script solved it carefully -- but AutomatedLab's
# RootDC role already owns forest creation and the reboot dance around it, so
# the whole mechanism is deleted rather than ported. The same reasoning removed
# provision/dc-baseline.ps1 from meta4/ad-vm.
#
# DOMAIN IS PINNED. hivestorm/common/roles.py used to draw domain_fqdn per seed;
# it now returns corp.sysrepair.local for S13. AutomatedLab fixes the forest at
# BUILD time, so a per-seed domain would mean a full rebuild per seed instead of
# a ~90-second snapshot restore. See the comment in _scenario_13.
#
# NETWORK. S13 gets its OWN switch on its own subnet. meta4/ad-vm owns
# SRB-Lab/10.20.30.0/24 and the two labs must never be co-resident on one
# address space -- the scenarios assume they are alone, and a stale ARP entry or
# a DNS answer from the wrong DC is exactly the sort of cross-talk that produces
# an unreproducible failure weeks later.
#
# .EXAMPLE
#   .\Hs13Lab.ps1                 # build
#   .\Hs13Lab.ps1 -WhatIfOnly     # validate preflight without building

[CmdletBinding()]
param(
    [string] $LabSourcesPath,
    [switch] $WhatIfOnly
)

$ErrorActionPreference = 'Stop'

$labName    = 'HS13'
$domainName = 'corp.sysrepair.local'
$dcName     = 'hs13-dc01'
$switchName = 'SRB-HS13'
$addressSpc = '10.20.13.0/24'
$dcAddress  = '10.20.13.5'
$adminUser  = 'Administrator'
$adminPass  = 'Password1!'

# Install-Lab exact-matches this string against what the ISO offers. See
# meta4/ad-vm/lab/SysRepairLab.ps1 for the full account of why an inexact name
# fails with "could not be found in the available operating systems".
$osName = 'Windows Server 2019 Datacenter Evaluation (Desktop Experience)'

# --- LabSources preflight, BEFORE Import-Module AutomatedLab -----------------
#
# Import-Module AutomatedLab resolves its LabSources location at import time and
# throws "Cannot bind argument to parameter 'Path'" if the folder is absent. The
# skeleton therefore has to exist first; creating it afterwards is too late.
if (-not $LabSourcesPath) { $LabSourcesPath = 'C:\LabSources' }
foreach ($d in 'ISOs', 'OSUpdates', 'SoftwarePackages', 'PostInstallationActivities', 'Tools') {
    $p = Join-Path $LabSourcesPath $d
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

$isoDir = Join-Path $LabSourcesPath 'ISOs'
$isos = @(Get-ChildItem -Path $isoDir -Filter '*.iso' -ErrorAction SilentlyContinue)
if ($isos.Count -eq 0) {
    throw @"
[hs13] No ISO in $isoDir.
S13 needs the same Windows Server 2019 Evaluation ISO meta4/ad-vm uses; see
meta4/ad-vm/lab/IMAGES.md for the download and checksum.
"@
}
Write-Host "[hs13] LabSources OK: $LabSourcesPath ($($isos.Count) ISO(s))"

Import-Module AutomatedLab -ErrorAction Stop

$available = (Get-LabAvailableOperatingSystem -Path $isoDir).OperatingSystemName
if ($available -notcontains $osName) {
    throw @"
[hs13] '$osName' is not among the available operating systems.
Install-Lab exact-matches this string. What the ISO actually offers:
$($available | ForEach-Object { "  - $_" } | Out-String)
Update `$osName in this script to one of the above.
"@
}

if ($WhatIfOnly) {
    Write-Host '[hs13] preflight OK; -WhatIfOnly set, not building'
    return
}

# --- switch collision guard --------------------------------------------------
#
# Refuse to build if something already owns this subnet. Silently attaching to a
# pre-existing switch on the same address space is how two labs end up sharing a
# broadcast domain.
$existing = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
if ($existing -and $existing.SwitchType -ne 'Internal') {
    throw "[hs13] switch '$switchName' exists but is $($existing.SwitchType), expected Internal"
}

New-LabDefinition -Name $labName -DefaultVirtualizationEngine HyperV

Add-LabDomainDefinition -Name $domainName -AdminUser $adminUser -AdminPassword $adminPass

# Default switch type is Internal, which is what we want: no route off the host.
Add-LabVirtualNetworkDefinition -Name $switchName -AddressSpace $addressSpc

$common = @{
    OperatingSystem = $osName
    Network         = $switchName
    DomainName      = $domainName
    InstallationUserCredential = (New-Object System.Management.Automation.PSCredential(
        $adminUser, (ConvertTo-SecureString $adminPass -AsPlainText -Force)))
}

# MEMORY: -Memory alone yields STATIC memory. Adding -MinMemory or -MaxMemory
# switches Hyper-V to Dynamic Memory, and AD's ESE database sizes its cache to
# the memory present at boot -- a DC that is later ballooned down thrashes. Pass
# -Memory only, deliberately.
Add-LabMachineDefinition -Name $dcName @common `
    -IpAddress $dcAddress `
    -Roles RootDC `
    -Memory 3GB

Install-Lab

# INSTALL-LAB EXITING IS NOT THE SAME AS THE DC WORKING.
#
# On the first build here Install-Lab returned without throwing while the log
# said "Lab deployment seems to have failed. The following tests were not
# passed:" -- AutomatedLab runs a Pester suite afterwards and it had failed on
# AutomatedLabTest's Dynamics*.tests.ps1, roles this lab does not deploy. The
# forest was in fact fine.
#
# Both halves of that matter. A non-throwing Install-Lab is not evidence of a
# working DC, and AutomatedLab's own verdict is not evidence of a broken one.
# So neither is trusted: this asks the directory directly and only then claims
# the lab is installed.
. "$PSScriptRoot\Hs13Ops.ps1"
$probe = Wait-Hs13Ready -TimeoutSeconds 900
$dom = Invoke-Command -VMName $dcName -Credential (New-Object System.Management.Automation.PSCredential(
        'CORP\Administrator', (ConvertTo-SecureString $adminPass -AsPlainText -Force))) -ScriptBlock {
    Import-Module ActiveDirectory; (Get-ADDomain).DNSRoot
}
if ($dom -ne $domainName) {
    throw "[hs13] DC promoted into '$dom', expected '$domainName'"
}

Write-Host ''
Write-Host "[hs13] lab '$labName' installed and VERIFIED (domain answers as $dom)"
Write-Host "[hs13]   DC:     $dcName at $dcAddress"
Write-Host "[hs13]   domain: $domainName"
Write-Host "[hs13]   switch: $switchName ($addressSpc)"
Write-Host ''
Write-Host '[hs13] next: lab\Save-Hs13Baseline.ps1 to capture the clean snapshot'
