# Regenerate roles.json + task.md for one or all hivestorm scenarios.
#
# Usage (from repo root):
#   hivestorm\prepare.ps1              # all scenarios
#   hivestorm\prepare.ps1 01           # scenario-01-debian9 only
#   hivestorm\prepare.ps1 01 03 14     # multiple scenarios
#   hivestorm\prepare.ps1 01 -Seed 42  # reproducible seed

param(
    [string[]] $Scenarios = @(),
    [int]      $Seed      = -1
)

$ErrorActionPreference = "Stop"

$DIRS = @{
    "01" = "hivestorm/scenario-01-debian9"
    "02" = "hivestorm/scenario-02-ubuntu1604"
    "03" = "hivestorm/scenario-03-win10"
    "04" = "hivestorm/scenario-04-win2019"
    "05" = "hivestorm/scenario-05-win2016"
    "06" = "hivestorm/scenario-06-debian9-postgres"
    "07" = "hivestorm/scenario-07-ubuntu1804-samba"
    "08" = "hivestorm/scenario-08-win-iis"
    "09" = "hivestorm/scenario-09-ubuntu-nginx-phpbb"
    "10" = "hivestorm/scenario-10-ubuntu-faillock"
    "11" = "hivestorm/scenario-11-win-dc-dns"
    "12" = "hivestorm/scenario-12-centos7-lamp"
    "13" = "hivestorm/scenario-13-ad-dc-win2019"
    "14" = "hivestorm/scenario-14-freebsd13"
    "15" = "hivestorm/scenario-15-docker-host"
    "16" = "hivestorm/scenario-16-nginx-phpfpm"
}

$targets = if ($Scenarios.Count -gt 0) { $Scenarios } else { $DIRS.Keys | Sort-Object }

$python = Join-Path $PSScriptRoot "..\inspect_eval\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Error "Python venv not found at $python. Run 'uv sync' inside inspect_eval first."
    exit 1
}

$env:PYTHONPATH = Split-Path $PSScriptRoot -Parent  # repo root

foreach ($sid in $targets) {
    $dir = $DIRS[$sid]
    if (-not $dir -or -not (Test-Path $dir)) {
        Write-Warning "skip: scenario $sid (dir missing)"
        continue
    }
    $seedArgs = if ($Seed -ge 0) { @("--seed", $Seed) } else { @() }
    & $python -m hivestorm.common.roles `
        --scenario $sid `
        @seedArgs `
        --out         "$dir/build/roles.json" `
        --render-task "$dir/task.md"
}
