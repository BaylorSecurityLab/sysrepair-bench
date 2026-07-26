<#
.SYNOPSIS
Renders gate-results.json as a per-scenario table and a failure taxonomy.

.DESCRIPTION
Copes with BOTH serialisation shapes:

  * an array of records (what Invoke-FullGateRun writes now), and
  * a single record whose properties are parallel arrays, which is what
    piping a List[object] into ConvertTo-Json produces.

The second shape is why an earlier summary printed System.Object[] for every
column. Handling both means results captured before that fix are still
readable rather than being re-run at ~5 minutes per scenario.
#>

function Show-GateResults {
    [CmdletBinding()]
    param(
        [string] $Path = (Join-Path $PSScriptRoot '..\gate-results.json')
    )

    if (-not (Test-Path $Path)) { throw "Show-GateResults: $Path not found" }
    $raw = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json

    # Normalise to a list of per-scenario records.
    $records = @()
    if ($raw -is [System.Array]) {
        $records = $raw
    }
    elseif ($raw.Scenario -is [System.Array]) {
        for ($i = 0; $i -lt $raw.Scenario.Count; $i++) {
            $g = $raw.Gates
            $records += [pscustomobject]@{
                Scenario  = $raw.Scenario[$i]
                Validated = $raw.Validated[$i]
                Gates     = [pscustomobject]@{
                    gate1_poc_fails       = $g.gate1_poc_fails[$i]
                    gate1_not_harness_err = $g.gate1_not_harness_err[$i]
                    gate1_service_healthy = $g.gate1_service_healthy[$i]
                    gate2_solvable        = $g.gate2_solvable[$i]
                    gate3_sabotage        = $g.gate3_sabotage[$i]
                    gate4_not_restarted   = $g.gate4_not_restarted[$i]
                }
            }
        }
    }
    else { $records = @($raw) }

    $fmt = "{0,-4} {1,-6} {2,-6} {3,-6} {4,-6} {5,-6} {6}"
    Write-Host ($fmt -f 'scn', 'valid', 'g1poc', 'g1svc', 'g2', 'g3', 'g4')
    Write-Host ($fmt -f '---', '-----', '-----', '-----', '--', '--', '--')

    foreach ($r in $records) {
        $g = $r.Gates
        Write-Host ($fmt -f `
            ($r.Scenario -replace 'scenario-', ''),
            $r.Validated, $g.gate1_poc_fails, $g.gate1_service_healthy,
            $g.gate2_solvable, $g.gate3_sabotage, $g.gate4_not_restarted)
    }

    # --- failure taxonomy -------------------------------------------------
    # Grouping matters more than the count: each shape points at a different
    # class of defect and a different fix.
    $neverDetects = @($records | Where-Object { $_.Gates.gate1_poc_fails -eq $false })
    $fixNotSeen   = @($records | Where-Object { $_.Gates.gate1_poc_fails -eq $true -and $_.Gates.gate2_solvable -eq $false })
    $harnessErr   = @($records | Where-Object { $_.Gates.gate1_not_harness_err -eq $false })
    $svcSick      = @($records | Where-Object { $_.Gates.gate1_service_healthy -eq $false })
    $validated    = @($records | Where-Object { $_.Validated -eq $true })

    Write-Host ''
    Write-Host ('=' * 60)
    Write-Host "VALIDATED: $($validated.Count) / $($records.Count)"
    Write-Host ('=' * 60)

    if ($harnessErr) {
        Write-Host ''
        Write-Host "HARNESS ERROR (PoC exit 2 -- grader tool missing/broken): $(($harnessErr.Scenario) -join ', ')"
        Write-Host '  Not evidence of anything. Fix the tooling before reading any other gate.'
    }
    if ($neverDetects) {
        Write-Host ''
        Write-Host "NEVER DETECTS THE VULN (gate 1 PoC passed on a vulnerable box): $(($neverDetects.Scenario) -join ', ')"
        Write-Host '  Worst class: these score a PASS while testing nothing.'
    }
    if ($fixNotSeen) {
        Write-Host ''
        Write-Host "PENALISES A CORRECT FIX (gate 1 ok, gate 2 failed): $(($fixNotSeen.Scenario) -join ', ')"
        Write-Host '  The attack is detected but the remediation is not recognised --'
        Write-Host '  usually a denial signature the PoC does not match.'
    }
    if ($svcSick) {
        Write-Host ''
        Write-Host "SERVICE GATE UNHEALTHY AT BASELINE: $(($svcSick.Scenario) -join ', ')"
    }

    return $records
}
