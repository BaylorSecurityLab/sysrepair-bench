#Requires -RunAsAdministrator
<#
.SYNOPSIS
Applies the Hyper-V settings the lab's correctness depends on.
#>

function Set-LabVMHardening {
    <#
    .SYNOPSIS
    Disables automatic checkpoints, pins checkpoint type, and enforces the
    fixed-memory requirement on the DC and attacker.

    .DESCRIPTION
    Three things, each load-bearing:

    1. AUTOMATIC CHECKPOINTS. Client Hyper-V defaults
       AutomaticCheckpointsEnabled to $true, taking a checkpoint on EVERY VM
       start -- i.e. on every reset. That reintroduces exactly the live-state
       DC snapshot the cold-baseline model exists to avoid, and grows the
       AVHDX chain without bound. AutomatedLab also sets this $false at
       creation; this is belt-and-braces and, more importantly, asserted.

    2. CHECKPOINT TYPE. AutomatedLab sets CheckpointType = 'Production' at VM
       creation. Production checkpoints use VSS and quiesce the guest,
       producing an application-consistent RUNNING-state image. The replay
       model requires cold, crash-consistent checkpoints taken from a
       powered-off VM, so Standard is required and this switch is genuinely
       necessary rather than cosmetic.

    3. FIXED MEMORY. Set-VMMemory is called explicitly because no other step
       enforces it: AutomatedLab turns Dynamic Memory ON whenever -MinMemory
       or -MaxMemory is supplied, and turning it back off is not something the
       lab definition can express.
    #>
    [CmdletBinding()]
    param(
        [string[]] $VMName = @('corp-dc01', 'corp-ca01', 'corp-ws01', 'attacker01'),

        # Guests that must never balloon. The DC because AD's ESE database
        # sizes its cache at boot; attacker01 because it runs a Docker runtime
        # and an OOM-killed tooling container mid-PoC produces exactly the
        # nondeterministic false passes this work exists to eliminate.
        [string[]] $FixedMemoryVM = @('corp-dc01', 'attacker01'),
        [int64]    $FixedMemoryBytes = 3GB
    )

    foreach ($n in $VMName) {
        $vm = Get-VM -Name $n -ErrorAction SilentlyContinue
        if (-not $vm) { Write-Warning "Set-LabVMHardening: $n not found, skipping"; continue }

        if ($vm.State -ne 'Off') {
            Write-Warning "Set-LabVMHardening: $n is $($vm.State); memory changes require it to be Off. Stopping."
            Stop-VM -Name $n -Force
            while ((Get-VM -Name $n).State -ne 'Off') { Start-Sleep -Seconds 2 }
        }

        Set-VM -Name $n -AutomaticCheckpointsEnabled $false
        Set-VM -Name $n -CheckpointType Standard
        Set-VM -Name $n -AutomaticStartAction Nothing -AutomaticStopAction ShutDown

        if ($FixedMemoryVM -contains $n) {
            Set-VMMemory -VMName $n -DynamicMemoryEnabled $false -StartupBytes $FixedMemoryBytes
            Write-Host "[harden] $n : checkpoints off, Standard, FIXED $([int]($FixedMemoryBytes/1GB))GB"
        }
        else {
            Write-Host "[harden] $n : checkpoints off, Standard, dynamic memory permitted"
        }

        # Any automatic checkpoints taken during Install-Lab survive the switch
        # above. Remove them, or the AVHDX chain the baseline sits on is
        # already polluted.
        $auto = Get-VMSnapshot -VMName $n -ErrorAction SilentlyContinue |
                Where-Object { $_.SnapshotType -eq 'AutomaticCheckpoint' }
        foreach ($a in $auto) {
            Remove-VMSnapshot -VMSnapshot $a -Confirm:$false
            Write-Host "[harden] $n : removed automatic checkpoint '$($a.Name)'"
        }
    }
}

function Protect-ParentDisk {
    <#
    .SYNOPSIS
    Makes a differencing-disk parent read-only and Defender-excluded.
    .DESCRIPTION
    The Windows guests derive from a shared parent VHDX. A single corruption
    loses all of them simultaneously, so the parent is never booted to patch
    and never left writable.

    Resolve the parent path from a child disk rather than guessing:
        Get-LabParentDiskPath -VMName corp-dc01
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ParentVhdxPath
    )

    if (-not (Test-Path -LiteralPath $ParentVhdxPath)) {
        throw "Protect-ParentDisk: $ParentVhdxPath not found"
    }

    Set-ItemProperty -LiteralPath $ParentVhdxPath -Name IsReadOnly -Value $true

    try {
        Add-MpPreference -ExclusionPath (Split-Path $ParentVhdxPath -Parent) -ErrorAction Stop
    } catch {
        Write-Warning "Protect-ParentDisk: could not add a Defender exclusion ($($_.Exception.Message)). Add it by hand."
    }

    Write-Host "[harden] parent disk read-only + Defender-excluded: $ParentVhdxPath"
}

function Get-LabParentDiskPath {
    <#
    .SYNOPSIS
    Resolves the differencing-disk parent for a VM, so Protect-ParentDisk does
    not have to be told a path the operator has to hunt for.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $VMName)

    $disk = Get-VMHardDiskDrive -VMName $VMName | Select-Object -First 1
    if (-not $disk) { throw "Get-LabParentDiskPath: $VMName has no hard disk" }

    $vhd = Get-VHD -Path $disk.Path
    if (-not $vhd.ParentPath) {
        Write-Warning "Get-LabParentDiskPath: $VMName's disk is not a differencing disk"
        return $null
    }
    return $vhd.ParentPath
}
