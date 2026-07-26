#Requires -RunAsAdministrator
<#
.SYNOPSIS
Repairs an AutomatedLab base image whose EFI System partition was left empty.

.DESCRIPTION
AutomatedLab can finish creating a base image -- logging "Finished creating
base image" with no error -- while leaving the EFI System partition completely
empty. Every VM built from that image then fails Hyper-V's boot with:

    'corp-dc01' failed to boot an operating system.

and the guest sits at 0% CPU with heartbeat "No Contact" forever. Install-Lab
waits on it indefinitely, so the symptom presents as a hang rather than a
failure.

ROOT CAUSE: the host's bcdboot.exe cannot write boot files for a materially
older guest. On a Windows 11 26200 host targeting a Server 2019 image, the
host bcdboot fails with "Failure when attempting to copy boot files"
(exit 193). The image's OWN bcdboot.exe, invoked with an explicit locale,
succeeds. The partition layout is not the problem -- the ESP is correctly
typed (c12a7328-f81f-11d2-ba4b-00a0c93ec93b) and formatted FAT32; it is simply
never populated.

This is why AutomatedLab issues #1497 and #1662 read as intermittent and went
stale upstream: it only reproduces when the host is much newer than the guest.

.EXAMPLE
Repair-LabBaseImage -Verbose
Finds every BASE_*.vhdx under the lab VM path and repairs any with an empty ESP.

.EXAMPLE
Repair-LabBaseImage -Path 'E:\AutomatedLab-VMs\BASE_....vhdx'
#>

function Repair-LabBaseImage {
    [CmdletBinding()]
    param(
        # Specific base VHDX. Omit to scan $VMPath.
        [string]   $Path,

        # Where AutomatedLab put the VMs. Install-Lab logs this as
        # "Location of Hyper-V machines will be '<path>'".
        [string]   $VMPath = 'E:\AutomatedLab-VMs',

        # Report what would be repaired without touching anything.
        [switch]   $WhatIfOnly
    )

    $targets = if ($Path) {
        @(Get-Item -LiteralPath $Path -ErrorAction Stop)
    } else {
        @(Get-ChildItem -LiteralPath $VMPath -Filter 'BASE_*.vhdx' -ErrorAction Stop)
    }

    if (-not $targets) {
        Write-Warning "Repair-LabBaseImage: no BASE_*.vhdx found under $VMPath"
        return
    }

    $results = foreach ($t in $targets) {
        Write-Host "[repair] inspecting $($t.Name)"

        # A base image with children cannot be modified: a differencing disk
        # records its parent's identity and breaks if the parent changes.
        $children = Get-ChildItem -LiteralPath $VMPath -Recurse -Filter '*.vhdx' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -ne $t.FullName } |
            Where-Object {
                try { (Get-VHD -Path $_.FullName -ErrorAction Stop).ParentPath -eq $t.FullName } catch { $false }
            }

        if ($children -and -not $WhatIfOnly) {
            throw @"
Repair-LabBaseImage: '$($t.Name)' has differencing children:
$($children.FullName -join "`n")

Modifying a parent invalidates its children. Remove the child VMs and their
disks first (Remove-Lab, or Remove-VM plus deleting the per-VM folder), then
re-run this, then re-run Install-Lab.
"@
        }

        $mounted = $null
        $assigned = @()   # letters WE added, to be removed before dismount
        try {
            $mounted = Mount-VHD -Path $t.FullName -PassThru -ErrorAction Stop
            $dn = $mounted.DiskNumber
            Start-Sleep -Seconds 3

            $espPart = Get-Partition -DiskNumber $dn | Where-Object Type -eq 'System'
            $winPart = Get-Partition -DiskNumber $dn | Where-Object Type -eq 'Basic'

            if (-not $espPart) { throw "no EFI System partition in $($t.Name)" }
            if (-not $winPart) { throw "no Windows partition in $($t.Name)" }

            # Mount to DIRECTORY JUNCTIONS, never drive letters.
            #
            # Assigning a drive letter persists in the partition table, and
            # AutomatedLab builds its copy destination from $drive.DriveLetter:
            # two lettered partitions produce the array "S F" ("Cannot find
            # drive"), zero produce an empty path ("The given path's format is
            # not supported"). Removing a letter afterwards is also not
            # reliably persisted from a read-only mount. Directory access paths
            # sidestep all of it -- they mount, they unmount, and they leave
            # the drive-letter state exactly as found.
            $mountRoot = Join-Path ([IO.Path]::GetTempPath()) "srb-mnt-$PID"
            $espDir = Join-Path $mountRoot 'esp'
            $winDir = Join-Path $mountRoot 'win'
            New-Item -ItemType Directory -Path $espDir -Force | Out-Null
            New-Item -ItemType Directory -Path $winDir -Force | Out-Null

            Add-PartitionAccessPath -DiskNumber $dn -PartitionNumber $espPart.PartitionNumber -AccessPath $espDir -ErrorAction Stop
            Add-PartitionAccessPath -DiskNumber $dn -PartitionNumber $winPart.PartitionNumber -AccessPath $winDir -ErrorAction Stop
            Start-Sleep -Seconds 2
            $assigned += @{ Part = $espPart.PartitionNumber; Path = $espDir }
            $assigned += @{ Part = $winPart.PartitionNumber; Path = $winDir }

            $esp = $espDir
            $win = $winDir

            $bootloader = Join-Path $esp 'EFI\Microsoft\Boot\bootmgfw.efi'
            $alreadyOk  = Test-Path $bootloader

            if ($alreadyOk) {
                Write-Host "[repair] $($t.Name): ESP already populated, nothing to do"
                [pscustomobject]@{ Image = $t.Name; Action = 'none'; Bootable = $true }
                return
            }

            Write-Host "[repair] $($t.Name): ESP is EMPTY -- this image cannot boot" -ForegroundColor Yellow

            if ($WhatIfOnly) {
                [pscustomobject]@{ Image = $t.Name; Action = 'would-repair'; Bootable = $false }
                return
            }

            # Use the IMAGE's bcdboot, not the host's. A host much newer than
            # the guest fails with "Failure when attempting to copy boot files".
            $imageBcdboot = Join-Path $win 'Windows\System32\bcdboot.exe'
            if (-not (Test-Path $imageBcdboot)) {
                throw "no bcdboot.exe inside the image at $imageBcdboot -- the applied image is incomplete, which is a different problem"
            }

            Write-Host "[repair] running the image's own bcdboot"
            $out = & $imageBcdboot (Join-Path $win 'Windows') /s $esp /f UEFI /l en-us 2>&1
            $rc  = $LASTEXITCODE
            $out | ForEach-Object { Write-Host "  $_" }

            if ($rc -ne 0) {
                throw "bcdboot failed with exit code $rc against $($t.Name)"
            }
            if (-not (Test-Path $bootloader)) {
                throw "bcdboot reported success but $bootloader is still absent"
            }

            Write-Host "[repair] $($t.Name): bootloader written" -ForegroundColor Green
            [pscustomobject]@{ Image = $t.Name; Action = 'repaired'; Bootable = $true }
        }
        finally {
            # CRITICAL: remove any drive letter we assigned before dismounting.
            #
            # Drive-letter assignments persist in the image's partition table.
            # AutomatedLab mounts each new VM's disk and copies files to
            # "$($drive.DriveLetter)...". If more than one partition carries a
            # letter, that expression yields an ARRAY, which stringifies to
            # e.g. "S F" and Install-Lab dies with:
            #
            #   Copy-Item : Cannot find drive. A drive with the name 'S F'
            #   does not exist.
            #
            # So a repair that leaves letters behind fixes booting and breaks
            # provisioning. Clean up exactly what we added, and only that.
            if ($mounted -and $assigned) {
                foreach ($a in $assigned) {
                    try {
                        Remove-PartitionAccessPath -DiskNumber $mounted.DiskNumber `
                            -PartitionNumber $a.Part -AccessPath $a.Path -ErrorAction Stop
                        Write-Verbose "[repair] released access path $($a.Path)"
                    } catch {
                        Write-Warning "[repair] could not release access path $($a.Path): $($_.Exception.Message.Split([char]10)[0])"
                    }
                }
                Remove-Item -LiteralPath (Join-Path ([IO.Path]::GetTempPath()) "srb-mnt-$PID") -Recurse -Force -ErrorAction SilentlyContinue
            }
            if ($mounted) { Dismount-VHD -Path $t.FullName -ErrorAction SilentlyContinue }
        }
    }

    return $results
}

function Set-LabBaseImageDriveLetters {
    <#
    .SYNOPSIS
    Puts a base image into the exact drive-letter state AutomatedLab requires:
    a letter on the NTFS "System" volume, and on nothing else.

    .DESCRIPTION
    AutomatedLabWorker locates the volume to copy its modules into with:

        $drive = $mountedosdisk | Get-Disk | Get-Partition | Get-Volume |
                 Where { $_.DriveLetter -and $_.FileSystemLabel -eq 'System' }

    then builds a path as "$($drive.DriveLetter):\Program Files\...". Two
    distinct ways to break that, and this project hit both:

      NO LETTER   -> $drive is null, the path becomes ":\Program Files\..." and
                     Copy-Item fails with "The given path's format is not
                     supported."

      TWO LETTERS -> PowerShell's -eq is CASE-INSENSITIVE, and a Windows image
                     carries BOTH a FAT32 EFI volume labelled "SYSTEM" and the
                     NTFS OS volume labelled "System". Letter them both and the
                     filter returns two volumes; "$($drive.DriveLetter)"
                     stringifies the array to "S F" and Copy-Item fails with
                     "Cannot find drive. A drive with the name 'S F' does not
                     exist."

    Windows does not reliably auto-assign a letter to a freshly mounted VHDX
    volume, so the letter is set explicitly here and inherited by every
    differencing child.
    #>
    [CmdletBinding()]
    param(
        [string] $VMPath = 'E:\AutomatedLab-VMs',
        [string] $Path,
        [char]   $Letter = 'V'
    )

    $targets = if ($Path) { @(Get-Item -LiteralPath $Path -ErrorAction Stop) }
               else { @(Get-ChildItem -LiteralPath $VMPath -Filter 'BASE_*.vhdx' -ErrorAction Stop) }

    foreach ($t in $targets) {
        $mounted = $null
        try {
            $mounted = Mount-VHD -Path $t.FullName -PassThru -ErrorAction Stop
            Start-Sleep -Seconds 4
            $parts = $mounted | Get-Disk | Get-Partition

            # 1. strip letters from everything that is not the OS volume
            foreach ($p in ($parts | Where-Object DriveLetter)) {
                $vol = $p | Get-Volume -ErrorAction SilentlyContinue
                $isOsVolume = $vol -and $vol.FileSystemType -eq 'NTFS' -and $vol.FileSystemLabel -ceq 'System'
                if (-not $isOsVolume) {
                    try {
                        Remove-PartitionAccessPath -DiskNumber $mounted.DiskNumber `
                            -PartitionNumber $p.PartitionNumber -AccessPath "$($p.DriveLetter):\" -ErrorAction Stop
                        Write-Host "[letters] $($t.Name): removed $($p.DriveLetter): from partition $($p.PartitionNumber) (label '$($vol.FileSystemLabel)')"
                    } catch {
                        Write-Warning "[letters] could not remove $($p.DriveLetter): -- $($_.Exception.Message.Split([char]10)[0])"
                    }
                }
            }

            # 2. ensure the OS volume HAS one. -ceq so the FAT32 'SYSTEM' ESP
            #    is not mistaken for the NTFS 'System' OS volume.
            $osPart = $parts | Where-Object {
                $v = $_ | Get-Volume -ErrorAction SilentlyContinue
                $v -and $v.FileSystemType -eq 'NTFS' -and $v.FileSystemLabel -ceq 'System'
            } | Select-Object -First 1

            if (-not $osPart) {
                Write-Warning "[letters] $($t.Name): no NTFS volume labelled 'System' found; AutomatedLab will not be able to locate it"
                continue
            }

            if ($osPart.DriveLetter) {
                Write-Host "[letters] $($t.Name): OS volume already has $($osPart.DriveLetter):"
            }
            else {
                $osPart | Set-Partition -NewDriveLetter $Letter -ErrorAction Stop
                Start-Sleep -Seconds 2
                Write-Host "[letters] $($t.Name): assigned ${Letter}: to the OS volume (partition $($osPart.PartitionNumber))"
            }
        }
        finally {
            if ($mounted) { Dismount-VHD -Path $t.FullName -ErrorAction SilentlyContinue }
        }
    }
}

function Clear-LabBaseImageDriveLetters {
    <#
    .SYNOPSIS
    Strips ALL drive-letter assignments from a base image's partitions.

    .DESCRIPTION
    Repairs an image that already carries persisted letters -- from an earlier
    repair, or from any manual mount where the letters were not removed. See
    the note in Repair-LabBaseImage's finally block for why they break
    Install-Lab.
    #>
    [CmdletBinding()]
    param(
        [string] $VMPath = 'E:\AutomatedLab-VMs',
        [string] $Path
    )

    $targets = if ($Path) { @(Get-Item -LiteralPath $Path -ErrorAction Stop) }
               else { @(Get-ChildItem -LiteralPath $VMPath -Filter 'BASE_*.vhdx' -ErrorAction Stop) }

    foreach ($t in $targets) {
        $mounted = $null
        try {
            $mounted = Mount-VHD -Path $t.FullName -PassThru -ErrorAction Stop
            Start-Sleep -Seconds 3

            $lettered = Get-Partition -DiskNumber $mounted.DiskNumber |
                        Where-Object DriveLetter

            if (-not $lettered) {
                Write-Host "[letters] $($t.Name): none assigned, OK"
                continue
            }

            foreach ($p in $lettered) {
                try {
                    Remove-PartitionAccessPath -DiskNumber $mounted.DiskNumber `
                        -PartitionNumber $p.PartitionNumber -AccessPath "$($p.DriveLetter):\" -ErrorAction Stop
                    Write-Host "[letters] $($t.Name): removed $($p.DriveLetter): from partition $($p.PartitionNumber)"
                } catch {
                    Write-Warning "[letters] $($t.Name): failed to remove $($p.DriveLetter): -- $($_.Exception.Message.Split([char]10)[0])"
                }
            }
        }
        finally {
            if ($mounted) { Dismount-VHD -Path $t.FullName -ErrorAction SilentlyContinue }
        }
    }
}

function Test-LabBaseImageBootable {
    <#
    .SYNOPSIS
    Reports whether each base image has a populated EFI System partition.
    .DESCRIPTION
    Read-only. Run this after Install-Lab creates base images and before it
    spends 45 minutes waiting on a VM that will never boot.
    #>
    [CmdletBinding()]
    param([string] $VMPath = 'E:\AutomatedLab-VMs')

    foreach ($t in (Get-ChildItem -LiteralPath $VMPath -Filter 'BASE_*.vhdx' -ErrorAction SilentlyContinue)) {
        $mounted  = $null
        $assigned = $null
        try {
            $mounted = Mount-VHD -Path $t.FullName -ReadOnly -PassThru -ErrorAction Stop
            Start-Sleep -Seconds 2
            $espPart = Get-Partition -DiskNumber $mounted.DiskNumber | Where-Object Type -eq 'System'

            # Directory access path, not a drive letter -- see the note in
            # Repair-LabBaseImage. A read-only CHECK must not be able to break
            # the build it exists to protect.
            $dir = Join-Path ([IO.Path]::GetTempPath()) "srb-chk-$PID"
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Add-PartitionAccessPath -DiskNumber $mounted.DiskNumber `
                -PartitionNumber $espPart.PartitionNumber -AccessPath $dir -ErrorAction Stop
            Start-Sleep -Seconds 2
            $assigned = @{ Part = $espPart.PartitionNumber; Path = $dir }

            $ok = Test-Path (Join-Path $dir 'EFI\Microsoft\Boot\bootmgfw.efi')
            [pscustomobject]@{ Image = $t.Name; Bootable = $ok }
        }
        catch {
            [pscustomobject]@{ Image = $t.Name; Bootable = "error: $($_.Exception.Message)" }
        }
        finally {
            # Even a read-only mount persists the drive-letter assignment in
            # the partition table. Leaving one here breaks Install-Lab with
            # "Cannot find drive. A drive with the name 'S F' does not exist"
            # -- so a read-only CHECK could break the build it was meant to
            # protect. Remove exactly what we assigned.
            if ($mounted -and $assigned) {
                try {
                    Remove-PartitionAccessPath -DiskNumber $mounted.DiskNumber `
                        -PartitionNumber $assigned.Part -AccessPath $assigned.Path -ErrorAction Stop
                } catch {
                    Write-Warning "[bootable] could not release access path $($assigned.Path): $($_.Exception.Message.Split([char]10)[0])"
                }
                Remove-Item -LiteralPath $assigned.Path -Recurse -Force -ErrorAction SilentlyContinue
            }
            if ($mounted) { Dismount-VHD -Path $t.FullName -ErrorAction SilentlyContinue }
        }
    }
}
