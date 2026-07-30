#Requires -RunAsAdministrator
<#
.SYNOPSIS
Builds meta4-dirtypipe: Ubuntu 20.04 on Hyper-V pinned to HWE kernel
5.13.0-27-generic, with Docker.

.DESCRIPTION
A profile plus thin wrappers over meta4/lib/HyperVVmBuild.psm1, which holds the
build logic shared with meta4/kernel-vm. Install-DirtyPipeLab stays the public
entry point; lab/hyperv.json names it as this VM's build_script.

WHY A SECOND KERNEL VM. Dirty Pipe (CVE-2022-0847) affects
5.8 <= k < 5.15.25 / 5.13.0-35 / 5.10.102. meta4-kernel pins 5.15.0-25, which is
22.04 GA and ALREADY carries the fix -- so meta4/scenario-19 could only be graded
there in compensating-control mode, never as a real exploit. USN-5317-1 landed the
fix in 5.13.0-35.40, so 20.04 HWE 5.13.0-27 is inside the affected window and the
real exploit path is reachable here. This VM hosts scenario-19 only.

NETWORKING. Two NICs, on purpose:

  eth0 -> 'Default Switch'  Hyper-V's NAT switch. DHCP + a route out for apt and
                            Docker's repo during the bake.
  eth1 -> SRB-Kernel        Internal, static 10.20.40.6. Shares the switch with
                            meta4-kernel on a different address and port, so both
                            VMs can be up at once.

Secure Boot is OFF, deliberately: Ubuntu's shim revokes superseded signed kernels
to prevent exactly the downgrade this VM performs on purpose. See the engine's
New-LabVm for the full reasoning.

.EXAMPLE
    . .\DirtyPipeLab.ps1
    Install-DirtyPipeLab
#>

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))) 'lib\HyperVVmBuild.psm1') -Force

# Not $script:Profile: PowerShell variable names are case-insensitive, so that
# name is the automatic $PROFILE variable and dot-sourcing this file would
# replace it with a hashtable for the rest of the session.
$script:LabProfile = @{
    Tag           = 'dirtypipe'
    VmName        = 'meta4-dirtypipe'
    Suite         = 'focal'
    KernelSeries  = '5.13.0'
    Abi           = 27
    AbiRationale  = 'inside the Dirty Pipe window; the fix landed at 5.13.0-35'
    CloudImage    = 'C:\LabSources\ISOs\focal-server-cloudimg-amd64.img'
    CloudImageSha = '18f2977d77dfea1b74aee14533bd21c34f789139e949c57023b7364894b7e5e9'
    BuildSwitch   = 'Default Switch'   # NAT; External-over-WiFi does not work
    LabSwitch     = 'SRB-Kernel'
    GuestUser     = 'vagrant'          # kept: run.py's docker-context contract
    GuestIp       = '10.20.40.6'
    GuestCidr     = '10.20.40.6/24'
    KeyPath       = Join-Path $HOME '.ssh\srb_dirtypipe'
    KeyComment    = 'srb-dirtypipe'
    # Static MACs. Hyper-V only assigns a dynamic MAC at first start, which is
    # after the seed ISO has to exist -- and cloud-init matches interfaces by MAC.
    # Fixing them here removes the ordering problem and makes rebuilds
    # reproducible.
    NatMac        = '00:15:5D:40:06:01'
    LabMac        = '00:15:5D:40:06:02'
    VhdRoot       = 'C:\ProgramData\Microsoft\Windows\Virtual Hard Disks'
    ScenarioDir   = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}

function New-DirtyPipeSshKey        { New-LabSshKey -Lab $script:LabProfile }
function Test-DirtyPipeCloudImage   { Test-LabCloudImage -Lab $script:LabProfile }
function Remove-DirtyPipeVm         { Remove-LabVm -Lab $script:LabProfile }
function Wait-DirtyPipeProvisioned  { param([int] $TimeoutMinutes = 40) Wait-LabProvisioned -Lab $script:LabProfile -TimeoutMinutes $TimeoutMinutes }

function Convert-DirtyPipeImageToVhdx {
    param([Parameter(Mandatory)][string] $VhdxPath)
    Convert-LabImageToVhdx -Lab $script:LabProfile -VhdxPath $VhdxPath
}

function New-DirtyPipeSeedIso {
    param([Parameter(Mandatory)][string] $IsoPath,
          [Parameter(Mandatory)][string] $PublicKey)
    New-LabSeedIso -Lab $script:LabProfile -IsoPath $IsoPath -PublicKey $PublicKey
}

function New-DirtyPipeVm {
    param([Parameter(Mandatory)][string] $VhdxPath)
    New-LabVm -Lab $script:LabProfile -VhdxPath $VhdxPath
}

function Invoke-DirtyPipeSsh {
    param([Parameter(Mandatory)][string] $Command, [int] $ConnectTimeout = 6)
    Invoke-LabSsh -Lab $script:LabProfile -Command $Command -ConnectTimeout $ConnectTimeout
}

function Assert-DirtyPipeAbi {
    param([Parameter(Mandatory)][string] $Running)
    Assert-LabAbi -Lab $script:LabProfile -Running $Running
}

function Get-DirtyPipeIpAddress { $script:LabProfile.GuestIp }

function Install-DirtyPipeLab { Install-VmLab -Lab $script:LabProfile }
