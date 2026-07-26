#Requires -RunAsAdministrator
<#
.SYNOPSIS
Re-runs only the FAILED scenarios from a gate run, capturing PoC output so the
failures become diagnosable.

.DESCRIPTION
A full gate run costs ~5 minutes per scenario. When the run was performed by a
harness build that discarded PoC output -- or when you simply want the tool's
own words for the failures -- re-running all 20 to see a handful of messages is
wasteful.

This reads gate-results.json, selects the scenarios that failed, and re-runs
them with output capture. Each failure family needs a different piece of
evidence:

  PENALISES A CORRECT FIX   gate 1 passed, gate 2 failed. The interesting
                            output is what the PoC printed AFTER the reference
                            fix -- it usually contains the denial signature the
                            check failed to match, which is the fix.

  NEVER DETECTS THE VULN    gate 1 failed. The interesting output is what the
                            PoC printed on the VULNERABLE box -- it shows
                            whether the attack genuinely failed or the check is
                            simply blind to it.

Writes gate-diagnostics.json with the captured output per scenario.

.EXAMPLE
Invoke-GateDiagnostics                       # every failure from the last run
Invoke-GateDiagnostics -ScenarioId 01,04     # specific ones
#>

. "$PSScriptRoot/Test-ScenarioGates.ps1"
. "$PSScriptRoot/Show-GateResults.ps1"

function Invoke-GateDiagnostics {
    [CmdletBinding()]
    param(
        [string[]] $ScenarioId,
        [string]   $ResultPath = (Join-Path $PSScriptRoot '..\gate-results.json'),
        [string]   $OutputPath = (Join-Path $PSScriptRoot '..\gate-diagnostics.json')
    )

    if (-not $ScenarioId) {
        $records = Show-GateResults -Path $ResultPath 6>$null
        $ScenarioId = @($records |
            Where-Object { -not $_.Validated } |
            ForEach-Object { $_.Scenario -replace 'scenario-', '' })
    }

    # NORMALISE to two digits.
    #
    # `-ScenarioId 01,07` at a PowerShell prompt parses those as INTEGERS, so
    # 01 arrives as "1" and the harness looks for scenario-1, which does not
    # exist. Test-ScenarioGates' ValidatePattern rejects it correctly, but the
    # per-scenario try/catch below then records that usage error as a scenario
    # RESULT -- so a mis-invocation reads as "the scenario failed". Pad here,
    # and classify usage errors distinctly below.
    $ScenarioId = @($ScenarioId | ForEach-Object { '{0:D2}' -f [int]$_ })

    if (-not $ScenarioId) {
        Write-Host '[diag] nothing failed -- nothing to diagnose'
        return
    }

    Write-Host "[diag] re-running $($ScenarioId.Count) failed scenario(s): $($ScenarioId -join ', ')"
    Write-Host "[diag] roughly $([math]::Round($ScenarioId.Count * 5)) minutes"

    $diag = New-Object System.Collections.Generic.List[object]

    foreach ($id in $ScenarioId) {
        Write-Host ""
        Write-Host ("-" * 60)
        Write-Host "diagnosing scenario-$id"
        Write-Host ("-" * 60)

        try {
            $r = Test-ScenarioGates -ScenarioId $id
            $diag.Add([pscustomobject]@{
                Scenario     = $r.Scenario
                Validated    = $r.Validated
                Gate1Output  = $r.Gates.gate1_output
                Gate2Output  = $r.Gates.gate2_output
                Gates        = $r.Gates
            })
        }
        catch {
            $msg = $_.Exception.Message.Split([char]10)[0]

            # A usage error is NOT a scenario result. Recording it as one makes
            # a bad invocation look like a failing scenario, which is how the
            # first diagnostic pass silently produced two meaningless records.
            if ($msg -match 'Cannot validate argument|does not match the|Parameter set cannot be resolved|not found') {
                Write-Error "Invoke-GateDiagnostics: usage error for '$id' -- $msg"
                throw "aborting: '$id' is not a runnable scenario id"
            }

            $diag.Add([pscustomobject]@{
                Scenario    = "scenario-$id"
                Validated   = $false
                Gate1Output = $null
                Gate2Output = $null
                Gates       = @{ error = $msg }
            })
        }

        ConvertTo-Json -InputObject $diag.ToArray() -Depth 6 |
            Set-Content -LiteralPath $OutputPath -Encoding utf8
    }

    Write-Host ""
    Write-Host ("=" * 60)
    Write-Host "DIAGNOSTIC OUTPUT"
    Write-Host ("=" * 60)
    foreach ($d in $diag) {
        Write-Host ""
        Write-Host "### $($d.Scenario)"
        if ($d.Gate1Output) {
            Write-Host "  -- PoC on the VULNERABLE box (gate 1 did not fire) --"
            ($d.Gate1Output -split "`n" | Select-Object -Last 10) | ForEach-Object { "     $($_.TrimEnd())" }
        }
        if ($d.Gate2Output) {
            Write-Host "  -- PoC AFTER the reference fix (gate 2 failed) --"
            ($d.Gate2Output -split "`n" | Select-Object -Last 10) | ForEach-Object { "     $($_.TrimEnd())" }
        }
        if (-not $d.Gate1Output -and -not $d.Gate2Output) {
            Write-Host '  (no captured output -- scenario passed on re-run, or errored)'
        }
    }

    Write-Host ""
    Write-Host "diagnostics: $OutputPath"
    return $diag
}
