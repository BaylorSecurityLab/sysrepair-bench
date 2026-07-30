#Requires -RunAsAdministrator
<#
.SYNOPSIS
Builds meta4-kernel: Ubuntu 22.04 on Hyper-V pinned to kernel 5.15.0-25-generic,
with Docker, replacing the Vagrant/VirtualBox definition.

.DESCRIPTION
A profile plus thin wrappers over meta4/lib/HyperVVmBuild.psm1, which holds the
build logic shared with meta4/dirtypipe-vm. Install-KernelLab stays the public
entry point; lab/hyperv.json names it as this VM's build_script.

Deliberately NOT built by AutomatedLab -- its Linux support is materially thinner
than its Windows support, and this VM is a plain Docker host, not a domain. Same
reasoning as meta4/ad-vm/lab/New-AttackerVM.ps1, whose cloud-init/qemu-img
patterns the shared engine reuses.

THE KERNEL IS THE POINT. meta4 scenarios S21 (GameOverlay, CVE-2023-2640/32629),
S22 (nf_tables UAF, CVE-2024-1086) and S117 run as containers INSIDE this VM so
they share its kernel. ABI 25 (5.15.0-25, 22.04 GA, March 2022) predates the
jammy fix for both -- 5.15.0-177.187 for GameOverlay, 5.15.0-101.111 for
nf_tables. If the VM boots a fixed ABI the scenarios silently stop being
exploitable and verify.sh "passes" for the wrong reason, so Assert-LabAbi
hard-fails rather than continue.

NETWORKING. Two NICs, on purpose:

  eth0 -> 'Default Switch'  Hyper-V's NAT switch. DHCP + a route out for apt and
                            Docker's repo during the bake.
  eth1 -> SRB-Kernel        Internal, static 10.20.40.5. Always reachable from
                            the host, so nothing depends on guest tooling.

The first draft baked on SRB-Build (External) and moved the NIC afterwards,
copying New-AttackerVM. That does not work on this host: SRB-Build is bridged to
a *Wi-Fi* adapter, and Hyper-V External switches over wireless do not get the AP
to accept the guest's MAC, so the guest never gets DHCP and apt hangs with no
diagnostic. The NAT switch has no such problem.

Nor can host-side IP discovery use Get-VMNetworkAdapter's IPAddresses: that is
reported by the Key-Value Pair integration service, whose daemon
(linux-cloud-tools-virtual) is absent from stock Ubuntu cloud images -- KVP shows
"No Contact" and the list is empty. Hence the fixed address on eth1. The KVP
package is installed anyway so the field works for anyone looking later.

.EXAMPLE
    . .\KernelLab.ps1
    Install-KernelLab
#>

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))) 'lib\HyperVVmBuild.psm1') -Force

# Not $script:Profile: PowerShell variable names are case-insensitive, so that
# name is the automatic $PROFILE variable and dot-sourcing this file would
# replace it with a hashtable for the rest of the session.
$script:LabProfile = @{
    Tag           = 'kernel'
    VmName        = 'meta4-kernel'
    Suite         = 'jammy'
    KernelSeries  = '5.15.0'
    Abi           = 25
    AbiRationale  = 'below the jammy GameOverlay fix at 177 and nf_tables fix at 101'
    CloudImage    = 'C:\LabSources\ISOs\jammy-server-cloudimg-amd64.img'
    CloudImageSha = '63dd101826bf6f45c74c4c2e0e0872cfeec4232cb1afcb8aeef8bc16f6c3b1e0'
    BuildSwitch   = 'Default Switch'   # NAT; External-over-WiFi does not work
    LabSwitch     = 'SRB-Kernel'
    GuestUser     = 'vagrant'          # kept: run.py's docker-context contract
    GuestIp       = '10.20.40.5'
    GuestCidr     = '10.20.40.5/24'
    KeyPath       = Join-Path $HOME '.ssh\srb_kernel'
    KeyComment    = 'srb-kernel'
    # Static MACs. Hyper-V only assigns a dynamic MAC at first start, which is
    # after the seed ISO has to exist -- and cloud-init matches interfaces by MAC.
    # Fixing them here removes the ordering problem and makes rebuilds
    # reproducible.
    NatMac        = '00:15:5D:40:05:01'
    LabMac        = '00:15:5D:40:05:02'
    VhdRoot       = 'C:\ProgramData\Microsoft\Windows\Virtual Hard Disks'
    ScenarioDir   = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}

function New-KernelSshKey        { New-LabSshKey -Lab $script:LabProfile }
function Test-KernelCloudImage   { Test-LabCloudImage -Lab $script:LabProfile }
function Remove-KernelVm         { Remove-LabVm -Lab $script:LabProfile }
function Wait-KernelProvisioned  { param([int] $TimeoutMinutes = 40) Wait-LabProvisioned -Lab $script:LabProfile -TimeoutMinutes $TimeoutMinutes }

function Convert-KernelImageToVhdx {
    param([Parameter(Mandatory)][string] $VhdxPath)
    Convert-LabImageToVhdx -Lab $script:LabProfile -VhdxPath $VhdxPath
}

function New-KernelSeedIso {
    param([Parameter(Mandatory)][string] $IsoPath,
          [Parameter(Mandatory)][string] $PublicKey)
    New-LabSeedIso -Lab $script:LabProfile -IsoPath $IsoPath -PublicKey $PublicKey
}

function New-KernelVm {
    param([Parameter(Mandatory)][string] $VhdxPath)
    New-LabVm -Lab $script:LabProfile -VhdxPath $VhdxPath
}

function Invoke-KernelSsh {
    param([Parameter(Mandatory)][string] $Command, [int] $ConnectTimeout = 6)
    Invoke-LabSsh -Lab $script:LabProfile -Command $Command -ConnectTimeout $ConnectTimeout
}

function Assert-KernelAbi {
    param([Parameter(Mandatory)][string] $Running)
    Assert-LabAbi -Lab $script:LabProfile -Running $Running
}

function Get-KernelIpAddress { $script:LabProfile.GuestIp }

function Install-KernelLab { Install-VmLab -Lab $script:LabProfile }
