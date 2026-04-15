# Verification script for Scenario 18: Scheduled-task backdoor
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$taskName = 'Windows Update Assistant'
$taskPath = '\Microsoft\Windows\UpdateOrchestrator\'
$stageDir = 'C:\Users\Public\Updater'

###############################################################################
# PoC Check 1: the rogue scheduled task must be gone
###############################################################################
$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
if ($task) {
    Write-Host "FAIL [PoC]: scheduled task '$taskPath$taskName' still registered."
    exit 1
}
Write-Host "PASS [PoC]: rogue scheduled task unregistered."

###############################################################################
# PoC Check 2: the staging directory must be gone
###############################################################################
if (Test-Path $stageDir) {
    Write-Host "FAIL [PoC]: payload staging directory $stageDir still present."
    exit 1
}
Write-Host "PASS [PoC]: payload staging directory removed."

###############################################################################
# PoC Check 3: no other SYSTEM-run tasks pointing at user-writable staging dirs
###############################################################################
$suspicious = Get-ScheduledTask | Where-Object {
    $_.Principal.UserId -eq 'SYSTEM' -and
    ($_.Actions | Where-Object { $_.Execute -match 'Users\\Public|ProgramData\\Temp|\\Temp\\' -or $_.Arguments -match 'Users\\Public|ProgramData\\Temp|\\Temp\\' })
}
if ($suspicious) {
    Write-Host "FAIL [PoC]: other SYSTEM-run tasks still reference user-writable staging paths:"
    $suspicious | ForEach-Object { Write-Host "  - $($_.TaskPath)$($_.TaskName)" }
    exit 1
}
Write-Host "PASS [PoC]: no other SYSTEM tasks point at user-writable staging paths."

###############################################################################
# Regression Check: the Task Scheduler service itself is still healthy
###############################################################################
$svc = Get-Service -Name Schedule -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Host "FAIL [Regression]: Task Scheduler service (Schedule) is not running."
    exit 1
}
Write-Host "PASS [Regression]: Task Scheduler service still running."

Write-Host "All checks passed."
exit 0
