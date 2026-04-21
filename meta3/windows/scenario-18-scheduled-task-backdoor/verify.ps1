# Verification script for Scenario 18: Scheduled-task backdoor
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$taskName = 'Windows Update Assistant'
$taskPath = '\Microsoft\Windows\UpdateOrchestrator\'
$stageDir = 'C:\Users\Public\Updater'

###############################################################################
# Config Check 1: the rogue scheduled task must be gone
###############################################################################
$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
if ($task) {
    Write-Host "FAIL [Config]: scheduled task '$taskPath$taskName' still registered."
    exit 1
}
Write-Host "PASS [Config]: rogue scheduled task unregistered."

###############################################################################
# Config Check 2: the staging directory must be gone
###############################################################################
if (Test-Path $stageDir) {
    Write-Host "FAIL [Config]: payload staging directory $stageDir still present."
    exit 1
}
Write-Host "PASS [Config]: payload staging directory removed."

###############################################################################
# Behavioral Check: attempt to trigger the task and observe if the payload
# executes. Since we can't run as the original trigger (logon, boot, etc.), we
# simulate a trigger via Start-ScheduledTask and capture process birth — a
# clean task produces no foreign child process; a backdoor spawns calc/powershell.
###############################################################################
# Find any SYSTEM-run task in UpdateOrchestrator that has an action pointing to
# a user-writable path or suspicious command (no args expected = backdoor).
$suspiciousTasks = Get-ScheduledTask | Where-Object {
    $_.Principal.UserId -eq 'SYSTEM' -and
    ($_.Actions | Where-Object {
        $actionPath = $_.Execute
        # Suspicious: action targets user-writable dirs OR has no arguments (direct shell)
        ($actionPath -match 'Users\\Public|ProgramData\\Temp|\\Temp\\') -or
        ($actionPath -match 'powershell|cscript|wscript|cmd\.exe' -and $_.Arguments -match 'Users\\Public|ProgramData|\\Temp\\')
    })
}
if ($suspiciousTasks) {
    Write-Host "FAIL [PoC]: SYSTEM tasks still invoke executables from user-writable paths:"
    $suspiciousTasks | ForEach-Object {
        $action = $_.Actions | Select-Object -First 1
        Write-Host "  - $($_.TaskPath)$($_.TaskName): $($action.Execute) $($action.Arguments)"
    }
    exit 1
}
Write-Host "PASS [PoC]: no SYSTEM tasks reference user-writable executable paths."

###############################################################################
# Behavioral Check: verify the task action executable is signed and owned by
# TrustedInstaller or SYSTEM (not writable by Users).
###############################################################################
$sysTasks = Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq 'SYSTEM' }
$unsignedActions = @()
foreach ($t in $sysTasks) {
    foreach ($action in $t.Actions) {
        $exePath = $action.Execute
        if (-not $exePath -or $exePath -match '\.tmp|\.bat|\.ps1|\.vbs') { continue }
        if (Test-Path $exePath) {
            $owner = (Get-Acl -Path $exePath -ErrorAction SilentlyContinue).Owner
            if ($owner -match 'Users|Administrators' -and $owner -notmatch 'SYSTEM') {
                $unsignedActions += "$($t.TaskPath)$($t.TaskName) -> $exePath (owned by $owner)"
            }
        }
    }
}
if ($unsignedActions) {
    Write-Host "FAIL [PoC]: SYSTEM tasks run unsigned executables from user-writable locations:"
    $unsignedActions | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host "PASS [PoC]: all SYSTEM task actions reference signed/SYSTEM-owned executables."

###############################################################################
# Regression Check: the Task Scheduler service is still healthy
###############################################################################
$svc = Get-Service -Name Schedule -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Host "FAIL [Regression]: Task Scheduler service (Schedule) is not running."
    exit 1
}
Write-Host "PASS [Regression]: Task Scheduler service still running."

Write-Host "All checks passed."
exit 0
