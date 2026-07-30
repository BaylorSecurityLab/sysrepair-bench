#Requires -RunAsAdministrator
<#
.SYNOPSIS
Runtime ops for meta4-kernel. The Hyper-V replacement for `vagrant up` /
`vagrant ssh-config`.

.DESCRIPTION
A profile plus thin wrappers over meta4/lib/HyperVVmOps.psm1, which holds the
logic shared with meta4/dirtypipe-vm. The wrapper names are load-bearing:
run.py resolves them by name out of lab/hyperv.json.

meta4 scenarios 21/22/117 run as privileged containers INSIDE this VM so they
share its pinned 5.15.0-25 kernel; the host talks to its Docker daemon over SSH.
scenario-19 lives on meta4/dirtypipe-vm -- 5.15.0-25 already carries the Dirty
Pipe fix.

Build it first with KernelLab.ps1 :: Install-KernelLab.
#>

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))) 'lib\HyperVVmOps.psm1') -Force

$script:Profile = @{
    Tag          = 'kernel'
    VmName       = 'meta4-kernel'
    GuestUser    = 'vagrant'
    GuestIp      = '10.20.40.5'
    SshPort      = 2224              # HS13 owns 2223, dirtypipe 2225
    KeyPath      = Join-Path $HOME '.ssh\srb_kernel'
    KernelSeries = '5.15.0'
    ExpectAbi    = 25
}

# lab -> kernel-vm -> meta4. Scenario directories are siblings of kernel-vm, not
# children of it, so this needs the same three levels as the Import-Module above.
$script:Meta4Dir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

function Invoke-KernelSsh {
    param([Parameter(Mandatory)][string] $Command, [int] $ConnectTimeout = 6)
    Invoke-VmSsh -Profile $script:Profile -Command $Command -ConnectTimeout $ConnectTimeout
}

function Test-KernelVmExists   { [bool](Get-VM -Name $script:Profile.VmName -ErrorAction SilentlyContinue) }
function Test-KernelSshReachable { Test-VmSshReachable -Profile $script:Profile }
function Get-KernelIpAddress   { if (Test-VmRunning -Profile $script:Profile) { $script:Profile.GuestIp } else { $null } }
function Start-KernelVm        { param([int] $TimeoutSeconds = 300) Start-VmAndWait -Profile $script:Profile -TimeoutSeconds $TimeoutSeconds }
function Restore-KernelBaseline { Restore-VmBaseline -Profile $script:Profile }
function Set-KernelPortProxy   { Set-VmPortProxy -Profile $script:Profile }
function Test-KernelAbi        { Test-VmKernelAbi -Profile $script:Profile }
function Wait-KernelNetworkReady { param([int] $TimeoutSeconds = 180) Wait-VmNetworkReady -Profile $script:Profile -TimeoutSeconds $TimeoutSeconds }
function Get-KernelSshConfig   { Get-VmSshConfig -Profile $script:Profile }

function Copy-KernelScenarios {
    param([string[]] $Scenario = @('scenario-21','scenario-22','scenario-117'))
    Copy-VmScenarios -Profile $script:Profile -Meta4Dir $script:Meta4Dir -Scenario $Scenario
}

function Invoke-KernelScenarioTest {
    param([Parameter(Mandatory)][string] $Scenario)
    Invoke-VmScenarioTest -Profile $script:Profile -Scenario $Scenario
}

function Initialize-KernelHost {
    param([switch] $NoRestore)
    Initialize-VmHost -Profile $script:Profile -NoRestore:$NoRestore
}
