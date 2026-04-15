# run-sequential.ps1 — build & run one Meta3-Windows scenario at a time.
#
# Usage:
#   .\run-sequential.ps1                           # runs every scenario-*/ folder
#   .\run-sequential.ps1 -Scenarios 01-snmp,02-iis # runs only listed scenarios
#   .\run-sequential.ps1 -BuildBaseOnly            # (re)build sysrepair/meta3-win-base
#
# Expects Docker Desktop in Windows Containers mode on a Server 2019+ / Win10+ host.

[CmdletBinding()]
param(
    [string[]]$Scenarios,
    [switch]$BuildBaseOnly,
    [ValidateSet('process','hyperv')] [string]$Isolation = 'hyperv',
    [int]$SshHostPort   = 2222,
    [int]$WinRmHostPort = 5985
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$baseTag = 'sysrepair/meta3-win-base:ltsc2019'

function Invoke-Docker([string[]]$args) {
    Write-Host ">> docker $($args -join ' ')" -ForegroundColor Cyan
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "docker $($args -join ' ') failed with exit $LASTEXITCODE" }
}

# --- Build the shared base image once ---
Invoke-Docker @('build', '--isolation', $Isolation, '-t', $baseTag, (Join-Path $root 'base'))
if ($BuildBaseOnly) { return }

# --- Discover scenarios ---
$allScenarios = Get-ChildItem -Path $root -Directory -Filter 'scenario-*' |
    ForEach-Object { $_.Name -replace '^scenario-', '' } | Sort-Object
if ($Scenarios) {
    $allScenarios = $allScenarios | Where-Object { $Scenarios -contains $_ }
}
if (-not $allScenarios) { throw "No matching scenarios found under $root." }

Write-Host "Running scenarios: $($allScenarios -join ', ')" -ForegroundColor Green

foreach ($s in $allScenarios) {
    $tag       = "sysrepair/meta3-win-$s:latest"
    $container = "meta3-win-$s"
    $dir       = Join-Path $root "scenario-$s"

    Write-Host "`n=== [$s] build ===" -ForegroundColor Yellow
    Invoke-Docker @('build', '--isolation', $Isolation, '-t', $tag, $dir)

    # Ensure nothing is holding the ports from a prior run
    & docker rm -f $container 2>$null | Out-Null
    while (Get-NetTCPConnection -LocalPort $SshHostPort -State Listen -ErrorAction SilentlyContinue) {
        Write-Host "Waiting for TCP/$SshHostPort to release..." ; Start-Sleep -Seconds 2
    }

    Write-Host "=== [$s] run ===" -ForegroundColor Yellow
    Invoke-Docker @(
        'run', '-d', '--name', $container, '--isolation', $Isolation,
        '-p', "127.0.0.1:${SshHostPort}:22",
        '-p', "127.0.0.1:${WinRmHostPort}:5985",
        $tag
    )

    Write-Host "Scenario '$s' is running. Agent can reach it at:"
    Write-Host "  SSH   : ssh vagrant@localhost -p $SshHostPort  (password: vagrant)"
    Write-Host "  WinRM : http://localhost:$WinRmHostPort/wsman"
    Write-Host ""
    Write-Host "When the agent finishes its repair attempt, run:"
    Write-Host "  docker exec $container powershell -File C:/verify/verify.ps1"
    Write-Host "  docker rm -f $container"
    Write-Host ""
    Read-Host "Press <Enter> to tear down and move to the next scenario"

    & docker rm -f $container | Out-Null
}

Write-Host "`nAll scenarios complete." -ForegroundColor Green
