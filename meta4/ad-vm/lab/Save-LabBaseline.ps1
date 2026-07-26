#Requires -RunAsAdministrator

Import-Module "$PSScriptRoot/LabReadiness.psm1" -Force
. "$PSScriptRoot/Start-LabOrdered.ps1"

function Stop-LabVMCold {
    <#
    .SYNOPSIS
    Shuts a VM down and polls until it is genuinely Off.
    .DESCRIPTION
    The retired reset.sh issued a poweroff then slept a fixed 2 seconds before
    restoring, which can lose the race. Poll for state instead.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $VMName, [int] $TimeoutSeconds = 180)

    $vm = Get-VM -Name $VMName -ErrorAction Stop
    if ($vm.State -eq 'Off') { return }

    Stop-VM -Name $VMName -Force -ErrorAction SilentlyContinue

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((Get-VM -Name $VMName).State -eq 'Off') { Write-Host "[halt] $VMName off"; return }
        Start-Sleep -Seconds 3
    }

    Write-Warning "[halt] $VMName did not shut down gracefully; forcing"
    Stop-VM -Name $VMName -TurnOff -Force
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if ((Get-VM -Name $VMName).State -eq 'Off') { return }
        Start-Sleep -Seconds 2
    }
    throw "Stop-LabVMCold: $VMName still not Off after force"
}

function Wait-VMSnapshotMerge {
    <#
    .SYNOPSIS
    Blocks until Hyper-V has finished merging AVHDX files after a snapshot
    removal.
    .DESCRIPTION
    Remove-VMSnapshot returns BEFORE the merge completes. Taking or restoring
    a checkpoint while a merge is in flight is how differencing chains get
    corrupted -- and all Windows guests share one parent.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $VMName, [int] $TimeoutSeconds = 600)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
        if (-not $vm) { return }
        if ($vm.Status -notmatch 'Merging|Backing up|in progress') { return }
        Start-Sleep -Seconds 5
    }
    throw "Wait-VMSnapshotMerge: $VMName still merging after $TimeoutSeconds s"
}

function Save-LabBaseline {
    <#
    .SYNOPSIS
    Captures the cold `baseline` checkpoint on all four machines, atomically.

    .DESCRIPTION
    Three properties the retired bash implementation lacked:

      1. It asserts the lab is genuinely provisioned before capturing. A
         baseline taken from a half-provisioned DC poisons all 20 scenarios at
         once, and the old script delegated that check to a manual human wait
         documented in the README.

      2. Promotion is atomic ACROSS MACHINES. The previous baseline is renamed
         aside to `baseline-prev` for every VM, the new checkpoints are
         promoted for every VM, and only then is `baseline-prev` deleted. A
         failure at any point leaves every machine holding a usable baseline.
         Deleting the old checkpoint before renaming the new one -- as both the
         bash original and the first draft of this function did -- leaves a
         window where a VM has no baseline at all.

      3. It exits non-zero if any baseline is missing afterwards, rather than
         warning and succeeding.
    #>
    [CmdletBinding()]
    param(
        [string[]] $VMName = @('corp-dc01', 'corp-ca01', 'corp-ws01', 'attacker01'),

        # Non-DC machines to gate on. Narrow during bring-up, before
        # attacker01 exists.
        [ValidateSet('ca', 'ws', 'attacker')]
        [string[]] $Members = @('ca', 'ws', 'attacker')
    )

    Write-Host '[baseline] verifying the lab is fully provisioned before capture'
    $ready = Start-LabOrdered -Members $Members
    if ($ready | Where-Object { -not $_.Ready }) {
        throw 'Save-LabBaseline: lab is not fully ready; refusing to capture a poisoned baseline.'
    }

    # Provisioning sentinel. The retired capture-baselines.sh never checked
    # this, delegating it to a manual wait in the README.
    $bootstrapped = Invoke-Command -VMName 'corp-dc01' -Credential $script:LabCred -ScriptBlock {
        Test-Path 'C:\meta4-setup\BOOTSTRAP_COMPLETE'
    } -ErrorAction SilentlyContinue

    if (-not $bootstrapped) {
        Write-Warning '[baseline] C:\meta4-setup\BOOTSTRAP_COMPLETE absent on corp-dc01.'
        Write-Warning '[baseline] Under AutomatedLab, promotion and seeding are gated by Start-LabOrdered'
        Write-Warning '[baseline] and seed-directory.ps1 instead. Writing the marker now for continuity.'
        Invoke-Command -VMName 'corp-dc01' -Credential $script:LabCred -ScriptBlock {
            New-Item -ItemType Directory -Path 'C:\meta4-setup' -Force | Out-Null
            New-Item -ItemType File -Path 'C:\meta4-setup\BOOTSTRAP_COMPLETE' -Force | Out-Null
        }
    }

    $stamp = 'baseline-new'
    $prev  = 'baseline-prev'

    foreach ($vm in $VMName) { Stop-LabVMCold -VMName $vm }

    # --- 1. capture all, under a temporary name ---
    foreach ($vm in $VMName) {
        Get-VMSnapshot -VMName $vm -Name $stamp -ErrorAction SilentlyContinue |
            Remove-VMSnapshot -Confirm:$false
        Wait-VMSnapshotMerge -VMName $vm

        Checkpoint-VM -Name $vm -SnapshotName $stamp -Confirm:$false

        # Checkpoint-VM returns before Hyper-V has finished registering the
        # snapshot, so an immediate Rename-VMSnapshot fails with "Unable to
        # find a snapshot matching the given criteria" against a checkpoint
        # that demonstrably exists moments later. Poll for it.
        $deadline = (Get-Date).AddSeconds(120)
        $snap = $null
        while ((Get-Date) -lt $deadline) {
            $snap = Get-VMSnapshot -VMName $vm -Name $stamp -ErrorAction SilentlyContinue
            if ($snap) { break }
            Start-Sleep -Seconds 2
        }
        if (-not $snap) { throw "Save-LabBaseline: checkpoint '$stamp' on $vm never became visible" }

        Write-Host "[baseline] captured $stamp on $vm"
    }

    # --- 2. rename the existing baseline aside, for all ---
    foreach ($vm in $VMName) {
        $old = Get-VMSnapshot -VMName $vm -Name 'baseline' -ErrorAction SilentlyContinue
        if ($old) {
            Rename-VMSnapshot -VMSnapshot $old -NewName $prev -ErrorAction Stop
        }
    }

    # --- 3. promote the new one, for all ---
    # Rename by OBJECT, not by name, and fail loudly. The previous version used
    # name matching with default (non-terminating) error handling, so a failed
    # rename still printed "promoted" -- reporting success for work that had
    # not happened.
    foreach ($vm in $VMName) {
        $new = Get-VMSnapshot -VMName $vm -Name $stamp -ErrorAction SilentlyContinue
        if (-not $new) { throw "Save-LabBaseline: '$stamp' missing on $vm at promotion time" }
        Rename-VMSnapshot -VMSnapshot $new -NewName 'baseline' -ErrorAction Stop
        Write-Host "[baseline] promoted $vm"
    }

    # --- 4. only now discard the old ---
    foreach ($vm in $VMName) {
        Get-VMSnapshot -VMName $vm -Name $prev -ErrorAction SilentlyContinue |
            Remove-VMSnapshot -Confirm:$false
        Wait-VMSnapshotMerge -VMName $vm
    }

    $missing = $VMName | Where-Object {
        -not (Get-VMSnapshot -VMName $_ -Name 'baseline' -ErrorAction SilentlyContinue)
    }
    if ($missing) {
        throw "Save-LabBaseline: no baseline on $($missing -join ', ')"
    }

    Write-Host "[baseline] all $($VMName.Count) baselines captured and promoted"
}
