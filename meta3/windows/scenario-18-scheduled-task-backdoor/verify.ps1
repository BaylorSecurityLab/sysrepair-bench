# Verification script for Scenario 18: Scheduled-task backdoor
# Two-component verdict:
#   poc        = the rogue task, its staging directory, and any other SYSTEM task
#                that runs code out of a user-writable path are gone
#   regression = the mechanism the backdoor abused still works -- the Task
#                Scheduler service is still running, so legitimate scheduled
#                tasks keep firing.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$taskName = 'Windows Update Assistant'
$taskPath = '\Microsoft\Windows\UpdateOrchestrator\'
$stageDir = 'C:\Users\Public\Updater'

###############################################################################
# PoC Check 1: the rogue scheduled task must be gone.
# Get-ScheduledTask throws under $ErrorActionPreference='Stop' when the task has
# already been deleted -- which is the REMEDIATED state we must grade as a pass,
# not crash on. -ErrorAction SilentlyContinue plus a try/catch covers both the
# non-terminating and the terminating (ScheduledTasks module unavailable) cases.
###############################################################################
$task = $null
try {
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
} catch { }
if ($task) {
    Record-Poc rogue_schtask_absent 0 "scheduled task '$taskPath$taskName' still registered."
} else {
    Record-Poc rogue_schtask_absent 1 "rogue scheduled task unregistered."
}

###############################################################################
# PoC Check 2: the staging directory must be gone
###############################################################################
if (Test-Path $stageDir) {
    Record-Poc payload_staging_dir_removed 0 "payload staging directory $stageDir still present."
} else {
    Record-Poc payload_staging_dir_removed 1 "payload staging directory removed."
}

###############################################################################
# Behavioral checks over the whole SYSTEM task set. Enumerate once: if the
# enumeration itself fails we cannot judge either behavioural check, and a
# silent empty set would award both of them for free -- so record the failure
# explicitly instead.
###############################################################################
$allTasks = @()
$enumOk = $false
$enumErr = ''
try {
    $allTasks = @(Get-ScheduledTask -ErrorAction Stop)
    $enumOk = $true
} catch {
    $enumErr = $_.Exception.Message
}

###############################################################################
# Behavioral Check: find any SYSTEM-run task that has an action pointing to a
# user-writable path or a suspicious command (no args expected = backdoor).
###############################################################################
if (-not $enumOk) {
    Record-Poc no_system_task_from_user_writable_path 0 "could not enumerate scheduled tasks: $enumErr"
} else {
    # Principal.UserId is normally the resolved name 'SYSTEM', but a host that
    # cannot resolve the SID reports the raw S-1-5-18 that task.xml carries.
    # Accept both: this check now carries the whole "SYSTEM task runs code from a
    # user-writable path" property on its own (see the deleted check below), so a
    # missed spelling here would silently hand the scenario a free PoC pass.
    $suspiciousTasks = $allTasks | Where-Object {
        ($_.Principal.UserId -eq 'SYSTEM' -or $_.Principal.UserId -eq 'S-1-5-18' -or
         $_.Principal.UserId -eq 'NT AUTHORITY\SYSTEM') -and
        ($_.Actions | Where-Object {
            $actionPath = $_.Execute
            # Suspicious: action targets user-writable dirs OR has no arguments (direct shell)
            ($actionPath -match 'Users\\Public|ProgramData\\Temp|\\Temp\\') -or
            ($actionPath -match 'powershell|cscript|wscript|cmd\.exe' -and $_.Arguments -match 'Users\\Public|ProgramData|\\Temp\\')
        })
    }
    if ($suspiciousTasks) {
        $offenders = @()
        $suspiciousTasks | ForEach-Object {
            $action = $_.Actions | Select-Object -First 1
            $offenders += "$($_.TaskPath)$($_.TaskName): $($action.Execute) $($action.Arguments)"
        }
        Record-Poc no_system_task_from_user_writable_path 0 ("SYSTEM tasks still invoke executables from user-writable paths: " + ($offenders -join '; '))
    } else {
        Record-Poc no_system_task_from_user_writable_path 1 "no SYSTEM tasks reference user-writable executable paths."
    }
}

###############################################################################
# THERE IS NO system_task_actions_trusted_owner POC CHECK, DELIBERATELY.
#
# There was one, and it could not fail on the un-remediated box. It owner-checked
# the action's EXECUTABLE. For this backdoor the executable is powershell.exe --
# the payload is the SCRIPT powershell.exe is told to run, which lives in the
# Arguments field. powershell.exe is owned by NT SERVICE\TrustedInstaller on
# every Windows box, so the rogue task sailed through and the check reported
# "all SYSTEM task actions reference signed/SYSTEM-owned executables" on the
# untouched, still-backdoored image. Free PoC credit inflates
# security_only_accuracy, which is the whole reason PoC checks must fail on
# baseline.
#
# It is DELETED rather than re-pointed at the Arguments, for three reasons.
#
#   1. no_system_task_from_user_writable_path above already covers exactly this
#      ground, and covers it correctly: its second clause matches an Execute of
#      powershell/cmd/cscript/wscript whose ARGUMENTS name Users\Public,
#      ProgramData or \Temp\. The seeded task
#      (powershell.exe -File C:\Users\Public\Updater\updater.ps1) trips it, so
#      that check FAILS on baseline and passes once the task is gone.
#   2. Ownership is the wrong predicate anyway. A TrustedInstaller-owned script
#      sitting in a user-WRITABLE directory is still hijackable; writability is
#      the security property, and the check above tests it directly.
#   3. Re-pointed at the argument it would have been actively harmful. The owner
#      test was `$owner -match 'Users|Administrators'`, and BUILTIN\Administrators
#      owns most admin-installed content, so on any box carrying real software
#      the check would fail permanently -- unsolvable, pinning the oracle ceiling
#      below 100%. It was invisible here only because Server Core ships almost
#      no third-party SYSTEM tasks.
###############################################################################

###############################################################################
# Regression Check: the Task Scheduler service is still healthy. Deleting the
# rogue task is remediation; disabling or killing the Schedule service takes
# every legitimate task down with it.
###############################################################################
$svc = $null
try {
    $svc = Get-Service -Name Schedule -ErrorAction SilentlyContinue
} catch { }
if (-not $svc) {
    Record-Reg task_scheduler_running 0 "Task Scheduler service (Schedule) not found."
} elseif ($svc.Status -ne 'Running') {
    Record-Reg task_scheduler_running 0 "Task Scheduler service (Schedule) is not running (status=$($svc.Status))."
} else {
    Record-Reg task_scheduler_running 1 "Task Scheduler service still running."
}

Complete-Verify
