#Requires -RunAsAdministrator
<#
.SYNOPSIS
Watchdog for Install-Lab. Detects the stall modes that otherwise present as an
indefinite hang.

.DESCRIPTION
Install-Lab has no internal timeout. When a VM fails to boot it simply waits,
forever, printing nothing. On this project that cost 35 minutes before anyone
noticed -- the giveaway was a VM in state Running at 0% CPU with heartbeat
"No Contact", which is what an unbootable base image looks like from outside.

This watchdog polls for three independent failure signatures and returns as
soon as one fires, instead of waiting on a build that will never finish:

  1. BOOT FAILURE   Hyper-V logs "failed to boot an operating system" for a
                    lab VM. Conclusive -- fails immediately.
  2. DEAD VM        A VM has been Running with 0% CPU and no heartbeat for
                    longer than -DeadVmMinutes. This is the unbootable-image
                    signature; the guest is powered on and executing nothing.
  3. LOG STALL      The Install-Lab log has not been written to for longer
                    than -StallMinutes. Base-image creation is legitimately
                    quiet for a couple of minutes, so keep this generous.

Plus an overall -TimeoutMinutes ceiling.

.EXAMPLE
Watch-LabInstall -LogPath C:\temp\install-lab.log -TimeoutMinutes 90

.OUTPUTS
[pscustomobject] Outcome, Reason, ElapsedMinutes, VMs
Outcome is one of: Completed, BootFailure, DeadVM, LogStall, Timeout
#>

function Watch-LabInstall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $LogPath,

        # Names to watch. Defaults to the lab's Windows machines; attacker01 is
        # built separately and is not part of Install-Lab.
        [string[]] $VMName = @('corp-dc01', 'corp-ca01', 'corp-ws01'),

        [int] $TimeoutMinutes  = 90,

        # A VM Running at 0% CPU with no heartbeat for this long is not slow,
        # it is not booting. Windows setup always shows CPU activity.
        [int] $DeadVmMinutes   = 8,

        # Base image creation writes nothing to the log for ~2.5 min, and the
        # per-VM wait is quiet for longer, so this is deliberately loose.
        [int] $StallMinutes    = 25,

        [int] $PollSeconds     = 30,

        # Marker that means Install-Lab finished. Matches the summary banner.
        [string] $CompletionPattern = 'Deployment (finished|complete)|Show-LabDeploymentSummary|installed and configured'
    )

    $start    = Get-Date
    $deadline = $start.AddMinutes($TimeoutMinutes)
    $deadSince = @{}

    # Staleness must be measured from when THIS watch began, not from the
    # file's age. A log left over from a previous run is already hours old and
    # would otherwise trip the stall rule on the first poll -- which is exactly
    # what happened the first time this ran: "no log output for 25.1 min"
    # reported 2 minutes in, against a log the current build had not yet
    # touched.
    $logSeenWriting = $false

    Write-Host "[watch] monitoring $LogPath (timeout ${TimeoutMinutes}m, dead-VM ${DeadVmMinutes}m, stall ${StallMinutes}m)"

    while ((Get-Date) -lt $deadline) {
        $elapsed = [math]::Round(((Get-Date) - $start).TotalMinutes, 1)
        $vms = Get-VM -Name $VMName -ErrorAction SilentlyContinue

        # --- 1. conclusive boot failure from Hyper-V itself ---
        $bootFail = Get-WinEvent -FilterHashtable @{
                        LogName   = 'Microsoft-Windows-Hyper-V-Worker-Admin'
                        StartTime = $start
                    } -ErrorAction SilentlyContinue |
                    Where-Object { $_.Message -match 'failed to boot an operating system' } |
                    Select-Object -First 1

        if ($bootFail) {
            return [pscustomobject]@{
                Outcome        = 'BootFailure'
                Reason         = $bootFail.Message.Trim()
                ElapsedMinutes = $elapsed
                VMs            = $vms | Select-Object Name, State
                Hint           = 'Base image is almost certainly unbootable. Run: Test-LabBaseImageBootable, then Repair-LabBaseImage.'
            }
        }

        # --- 2. running but executing nothing ---
        foreach ($vm in ($vms | Where-Object State -eq 'Running')) {
            $hb = (Get-VMIntegrationService -VMName $vm.Name -Name Heartbeat -ErrorAction SilentlyContinue).PrimaryStatusDescription
            $isDead = ($vm.CPUUsage -eq 0) -and ($hb -ne 'OK')

            if ($isDead) {
                if (-not $deadSince.ContainsKey($vm.Name)) { $deadSince[$vm.Name] = Get-Date }
                $deadFor = ((Get-Date) - $deadSince[$vm.Name]).TotalMinutes

                if ($deadFor -ge $DeadVmMinutes) {
                    return [pscustomobject]@{
                        Outcome        = 'DeadVM'
                        Reason         = "$($vm.Name) has been Running at 0% CPU with heartbeat '$hb' for $([math]::Round($deadFor,1)) min"
                        ElapsedMinutes = $elapsed
                        VMs            = $vms | Select-Object Name, State, CPUUsage
                        Hint           = 'This is the unbootable-base-image signature. Run: Test-LabBaseImageBootable.'
                    }
                }
            }
            else {
                $deadSince.Remove($vm.Name) | Out-Null
            }
        }

        # --- 3. blocked on a stale deployment lock ---
        # AutomatedLab refuses to deploy disks while this file exists and waits
        # indefinitely rather than failing. A killed run leaves it behind, so
        # every subsequent Install-Lab silently blocks here forever.
        $lockFile = 'C:\ProgramData\AutomatedLab\LabDiskDeploymentInProgress.txt'
        if (Test-Path -LiteralPath $lockFile) {
            $lockAge = [math]::Round(((Get-Date) - (Get-Item -LiteralPath $lockFile).LastWriteTime).TotalMinutes, 1)
            return [pscustomobject]@{
                Outcome        = 'DeploymentLock'
                Reason         = "AutomatedLab disk-deployment lock present (age ${lockAge}m): $lockFile"
                ElapsedMinutes = $elapsed
                VMs            = $vms | Select-Object Name, State
                Hint           = "Left behind by an interrupted run. Confirm no other Install-Lab is active, then: Remove-Item '$lockFile' -Force"
            }
        }

        # --- 4. log gone quiet ---
        if (Test-Path -LiteralPath $LogPath) {
            $lastWrite = (Get-Item -LiteralPath $LogPath).LastWriteTime
            if ($lastWrite -ge $start) { $logSeenWriting = $true }

            # Only apply the stall rule once the current run has demonstrably
            # written to this log; otherwise a leftover file reads as a stall.
            $quietFor = if ($logSeenWriting) { ((Get-Date) - $lastWrite).TotalMinutes } else { 0 }

            if ($quietFor -ge $StallMinutes) {
                return [pscustomobject]@{
                    Outcome        = 'LogStall'
                    Reason         = "no log output for $([math]::Round($quietFor,1)) min"
                    ElapsedMinutes = $elapsed
                    VMs            = $vms | Select-Object Name, State, CPUUsage
                    Hint           = 'Check the log tail and the Hyper-V console for the affected VM.'
                }
            }

            $tail = Get-Content -LiteralPath $LogPath -Tail 40 -ErrorAction SilentlyContinue
            if ($logSeenWriting -and $tail -match $CompletionPattern) {
                return [pscustomobject]@{
                    Outcome        = 'Completed'
                    Reason         = 'completion marker found in log'
                    ElapsedMinutes = $elapsed
                    VMs            = $vms | Select-Object Name, State
                    Hint           = $null
                }
            }
        }

        $running = ($vms | Where-Object State -eq 'Running' | Measure-Object).Count
        Write-Host ("[watch] {0,5:N1}m  vms={1} running={2}" -f $elapsed, $vms.Count, $running)
        Start-Sleep -Seconds $PollSeconds
    }

    return [pscustomobject]@{
        Outcome        = 'Timeout'
        Reason         = "exceeded ${TimeoutMinutes} min"
        ElapsedMinutes = [math]::Round(((Get-Date) - $start).TotalMinutes, 1)
        VMs            = Get-VM -Name $VMName -ErrorAction SilentlyContinue | Select-Object Name, State
        Hint           = 'Install-Lab has no internal timeout; inspect the log and the VM consoles.'
    }
}
