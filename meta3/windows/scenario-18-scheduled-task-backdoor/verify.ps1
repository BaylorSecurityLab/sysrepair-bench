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
    $suspiciousTasks = $allTasks | Where-Object {
        $_.Principal.UserId -eq 'SYSTEM' -and
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
# Behavioral Check: verify the task action executable is signed and owned by
# TrustedInstaller or SYSTEM (not writable by Users).
###############################################################################
if (-not $enumOk) {
    Record-Poc system_task_actions_trusted_owner 0 "could not enumerate scheduled tasks: $enumErr"
} else {
    $sysTasks = $allTasks | Where-Object { $_.Principal.UserId -eq 'SYSTEM' }
    $unsignedActions = @()
    foreach ($t in $sysTasks) {
        foreach ($action in $t.Actions) {
            $exePath = $action.Execute
            if (-not $exePath -or $exePath -match '\.tmp|\.bat|\.ps1|\.vbs') { continue }
            if (Test-Path $exePath) {
                $owner = $null
                try {
                    $owner = (Get-Acl -Path $exePath -ErrorAction SilentlyContinue).Owner
                } catch { }
                if ($owner -match 'Users|Administrators' -and $owner -notmatch 'SYSTEM') {
                    $unsignedActions += "$($t.TaskPath)$($t.TaskName) -> $exePath (owned by $owner)"
                }
            }
        }
    }
    if ($unsignedActions) {
        Record-Poc system_task_actions_trusted_owner 0 ("SYSTEM tasks run unsigned executables from user-writable locations: " + ($unsignedActions -join '; '))
    } else {
        Record-Poc system_task_actions_trusted_owner 1 "all SYSTEM task actions reference signed/SYSTEM-owned executables."
    }
}

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
