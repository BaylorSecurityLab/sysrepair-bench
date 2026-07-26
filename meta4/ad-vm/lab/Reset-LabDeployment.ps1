#Requires -RunAsAdministrator
<#
.SYNOPSIS
Clears partial AutomatedLab deployment state so Install-Lab can be re-run,
while PRESERVING the expensive base image.

.DESCRIPTION
Install-Lab is not idempotent after a failed or interrupted run. Three distinct
kinds of leftover each block a retry, and each fails with a message that does
not name the others:

  1. PER-VM DISKS   "The disk E:\...\corp-dc01.vhdx does already exist. Disk
                    cannot be created" -- then, because the VM was never made,
                    "Could not start Hyper-V machine 'corp-dc01': No virtual
                    machine corp-dc01 found".
  2. DEPLOYMENT LOCK C:\ProgramData\AutomatedLab\LabDiskDeploymentInProgress.txt
                    survives a killed run, and Install-Lab then waits on it
                    indefinitely rather than failing.
  3. LAB DEFINITION C:\ProgramData\AutomatedLab\Labs\<name> holding stale
                    machine state.

The base image (BASE_*.vhdx) is deliberately NOT deleted. It takes ~2.5 minutes
to build and, on hosts where AutomatedLab leaves the EFI partition empty, has
been repaired by Repair-LabBaseImage -- throwing it away means redoing that
repair every retry.

.EXAMPLE
Reset-LabDeployment -WhatIfOnly     # show what would be removed
Reset-LabDeployment                 # clear it
#>

function Reset-LabDeployment {
    [CmdletBinding()]
    param(
        [string]   $LabName = 'SysRepairBench',
        [string]   $VMPath  = 'E:\AutomatedLab-VMs',
        [string[]] $VMName  = @('corp-dc01', 'corp-ca01', 'corp-ws01'),

        # Also delete BASE_*.vhdx. Off by default -- see above.
        [switch]   $IncludeBaseImage,

        [switch]   $WhatIfOnly
    )

    $actions = New-Object System.Collections.Generic.List[string]

    # --- 1. VMs ---
    foreach ($n in $VMName) {
        $vm = Get-VM -Name $n -ErrorAction SilentlyContinue
        if ($vm) {
            $actions.Add("remove VM $n (state $($vm.State))")
            if (-not $WhatIfOnly) {
                if ($vm.State -ne 'Off') {
                    Stop-VM -Name $n -TurnOff -Force -ErrorAction SilentlyContinue
                    $deadline = (Get-Date).AddSeconds(60)
                    while ((Get-VM -Name $n -ErrorAction SilentlyContinue).State -ne 'Off' -and (Get-Date) -lt $deadline) {
                        Start-Sleep -Seconds 2
                    }
                }
                Remove-VM -Name $n -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # --- 2. per-VM disk folders ---
    foreach ($n in $VMName) {
        $dir = Join-Path $VMPath $n
        if (Test-Path -LiteralPath $dir) {
            $actions.Add("delete $dir")
            if (-not $WhatIfOnly) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # --- 3. deployment lock ---
    $lock = 'C:\ProgramData\AutomatedLab\LabDiskDeploymentInProgress.txt'
    if (Test-Path -LiteralPath $lock) {
        $age = [math]::Round(((Get-Date) - (Get-Item -LiteralPath $lock).LastWriteTime).TotalMinutes, 1)
        $actions.Add("remove deployment lock (age ${age}m)")
        if (-not $WhatIfOnly) { Remove-Item -LiteralPath $lock -Force -ErrorAction SilentlyContinue }
    }

    # --- 4. lab definition ---
    $labDir = Join-Path 'C:\ProgramData\AutomatedLab\Labs' $LabName
    if (Test-Path -LiteralPath $labDir) {
        $actions.Add("delete lab definition $labDir")
        if (-not $WhatIfOnly) { Remove-Item -LiteralPath $labDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    # --- 5. hosts-file entries AutomatedLab added ---
    # Best-effort and explicitly non-fatal: the hosts file is frequently locked
    # by another process, and stale entries do not block Install-Lab -- it
    # rewrites its own. Report the real outcome rather than assuming the write
    # landed.
    $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path -LiteralPath $hosts) {
        $lines = Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue
        $keep  = $lines | Where-Object { $_ -notmatch '(?i)\b(corp-dc01|corp-ca01|corp-ws01)\b' }
        $n     = $lines.Count - $keep.Count

        if ($n -gt 0) {
            if ($WhatIfOnly) {
                $actions.Add("strip $n lab entries from hosts file")
            }
            else {
                try {
                    Set-Content -LiteralPath $hosts -Value $keep -Encoding ascii -ErrorAction Stop
                    $actions.Add("stripped $n lab entries from hosts file")
                }
                catch {
                    $actions.Add("SKIPPED hosts file ($n stale entries left): $($_.Exception.Message.Split([char]10)[0])")
                    Write-Warning "[reset] could not rewrite the hosts file; $n stale lab entries remain. This does not block Install-Lab."
                }
            }
        }
    }

    # --- 6. base image, only on request ---
    if ($IncludeBaseImage) {
        foreach ($b in (Get-ChildItem -LiteralPath $VMPath -Filter 'BASE_*.vhdx' -ErrorAction SilentlyContinue)) {
            $actions.Add("delete base image $($b.Name)  [rebuild + re-repair required]")
            if (-not $WhatIfOnly) { Remove-Item -LiteralPath $b.FullName -Force -ErrorAction SilentlyContinue }
        }
    }
    else {
        $kept = Get-ChildItem -LiteralPath $VMPath -Filter 'BASE_*.vhdx' -ErrorAction SilentlyContinue
        foreach ($b in $kept) { Write-Host "[reset] preserving base image $($b.Name)" }
    }

    if (-not $actions) {
        Write-Host '[reset] nothing to clean'
        return
    }

    $verb = if ($WhatIfOnly) { 'would' } else { 'did' }
    foreach ($a in $actions) { Write-Host "[reset] $verb : $a" }

    if (-not $WhatIfOnly) { Write-Host "[reset] Install-Lab can now be re-run" }
}
