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
        try {
            $mounted = Mount-VHD -Path $t.FullName -PassThru -ErrorAction Stop
            $dn = $mounted.DiskNumber
            Start-Sleep -Seconds 3

            $espPart = Get-Partition -DiskNumber $dn | Where-Object Type -eq 'System'
            $winPart = Get-Partition -DiskNumber $dn | Where-Object Type -eq 'Basic'

            if (-not $espPart) { throw "no EFI System partition in $($t.Name)" }
            if (-not $winPart) { throw "no Windows partition in $($t.Name)" }

            if (-not $espPart.DriveLetter) {
                $espPart | Set-Partition -NewDriveLetter S
                Start-Sleep -Seconds 2
                $espPart = Get-Partition -DiskNumber $dn -PartitionNumber $espPart.PartitionNumber
            }
            if (-not $winPart.DriveLetter) {
                $winPart | Set-Partition -NewDriveLetter W
                Start-Sleep -Seconds 2
                $winPart = Get-Partition -DiskNumber $dn -PartitionNumber $winPart.PartitionNumber
            }

            $esp = $espPart.DriveLetter
            $win = $winPart.DriveLetter

            $bootloader = "${esp}:\EFI\Microsoft\Boot\bootmgfw.efi"
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
            $imageBcdboot = "${win}:\Windows\System32\bcdboot.exe"
            if (-not (Test-Path $imageBcdboot)) {
                throw "no bcdboot.exe inside the image at $imageBcdboot -- the applied image is incomplete, which is a different problem"
            }

            Write-Host "[repair] running the image's own bcdboot"
            $out = & $imageBcdboot "${win}:\Windows" /s "${esp}:" /f UEFI /l en-us 2>&1
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
            if ($mounted) { Dismount-VHD -Path $t.FullName -ErrorAction SilentlyContinue }
        }
    }

    return $results
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
        $mounted = $null
        try {
            $mounted = Mount-VHD -Path $t.FullName -ReadOnly -PassThru -ErrorAction Stop
            Start-Sleep -Seconds 2
            $espPart = Get-Partition -DiskNumber $mounted.DiskNumber | Where-Object Type -eq 'System'
            if (-not $espPart.DriveLetter) {
                $espPart | Set-Partition -NewDriveLetter S
                Start-Sleep -Seconds 2
                $espPart = Get-Partition -DiskNumber $mounted.DiskNumber -PartitionNumber $espPart.PartitionNumber
            }
            $ok = Test-Path "$($espPart.DriveLetter):\EFI\Microsoft\Boot\bootmgfw.efi"
            [pscustomobject]@{ Image = $t.Name; Bootable = $ok }
        }
        catch {
            [pscustomobject]@{ Image = $t.Name; Bootable = "error: $($_.Exception.Message)" }
        }
        finally {
            if ($mounted) { Dismount-VHD -Path $t.FullName -ErrorAction SilentlyContinue }
        }
    }
}
