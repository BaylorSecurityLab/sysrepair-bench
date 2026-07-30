#Requires -RunAsAdministrator
<#
.SYNOPSIS
Runtime ops for meta4-dirtypipe. The Hyper-V replacement for `vagrant up` /
`vagrant ssh-config`.

.DESCRIPTION
A profile plus thin wrappers over meta4/lib/HyperVVmOps.psm1, which holds the
logic shared with meta4/kernel-vm. The wrapper names are load-bearing: run.py
resolves them by name out of lab/hyperv.json.

This VM exists for meta4/scenario-19 only. Dirty Pipe (CVE-2022-0847) affects
5.8 <= k < 5.13.0-35, so meta4-kernel's 5.15.0-25 already carries the fix and can
only grade the scenario through the chattr +i compensating control. 5.13.0-27 is
inside the affected window, so the real exploit path is reachable here.

Shares the SRB-Kernel switch with meta4-kernel on a different address and port,
so both VMs can be up at once.

Build it first with DirtyPipeLab.ps1 :: Install-DirtyPipeLab.
#>

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))) 'lib\HyperVVmOps.psm1') -Force

$script:Profile = @{
    Tag          = 'dirtypipe'
    VmName       = 'meta4-dirtypipe'
    GuestUser    = 'vagrant'
    GuestIp      = '10.20.40.6'
    SshPort      = 2225              # HS13 owns 2223, kernel-vm 2224
    KeyPath      = Join-Path $HOME '.ssh\srb_dirtypipe'
    KernelSeries = '5.13.0'
    ExpectAbi    = 27
}

# lab -> dirtypipe-vm -> meta4. Scenario directories are siblings of
# dirtypipe-vm, not children of it, so this needs three levels.
$script:Meta4Dir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

function Invoke-DirtyPipeSsh {
    param([Parameter(Mandatory)][string] $Command, [int] $ConnectTimeout = 6)
    Invoke-VmSsh -Profile $script:Profile -Command $Command -ConnectTimeout $ConnectTimeout
}

function Test-DirtyPipeVmExists     { [bool](Get-VM -Name $script:Profile.VmName -ErrorAction SilentlyContinue) }
function Test-DirtyPipeSshReachable { Test-VmSshReachable -Profile $script:Profile }
function Get-DirtyPipeIpAddress     { if (Test-VmRunning -Profile $script:Profile) { $script:Profile.GuestIp } else { $null } }
function Start-DirtyPipeVm          { param([int] $TimeoutSeconds = 300) Start-VmAndWait -Profile $script:Profile -TimeoutSeconds $TimeoutSeconds }
function Restore-DirtyPipeBaseline  { Restore-VmBaseline -Profile $script:Profile }
function Set-DirtyPipePortProxy     { Set-VmPortProxy -Profile $script:Profile }
function Test-DirtyPipeAbi          { Test-VmKernelAbi -Profile $script:Profile }
function Wait-DirtyPipeNetworkReady { param([int] $TimeoutSeconds = 180) Wait-VmNetworkReady -Profile $script:Profile -TimeoutSeconds $TimeoutSeconds }
function Get-DirtyPipeSshConfig     { Get-VmSshConfig -Profile $script:Profile }

function Copy-DirtyPipeScenarios {
    param([string[]] $Scenario = @('scenario-19'))
    Copy-VmScenarios -Profile $script:Profile -Meta4Dir $script:Meta4Dir -Scenario $Scenario
}

function Invoke-DirtyPipeScenarioTest {
    param([Parameter(Mandatory)][string] $Scenario)
    Invoke-VmScenarioTest -Profile $script:Profile -Scenario $Scenario
}

function Initialize-DirtyPipeHost {
    param([switch] $NoRestore)
    Initialize-VmHost -Profile $script:Profile -NoRestore:$NoRestore
}
