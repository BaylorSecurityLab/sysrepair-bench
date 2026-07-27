#Requires -RunAsAdministrator
<#
.SYNOPSIS
Runs every scenario through the four proof gates and writes a results file.

.DESCRIPTION
This is the acceptance gate for the whole suite. Each scenario is restored to
baseline, injected, fixed and sabotaged, so a run is roughly 4-5 minutes per
scenario.

A scenario counts as VALIDATED only when gates 1-3 hold. Gate 4 is reported
separately because it is not applicable everywhere -- a remediation that is a
pure directory change has no service to leave unrestarted.

Results are written as JSON so a partial run is not lost if the host is
interrupted; each scenario is appended as it completes.
#>

. "$PSScriptRoot/Test-ScenarioGates.ps1"

function Invoke-FullGateRun {
    [CmdletBinding()]
    param(
        [string[]] $ScenarioId = @('01','02','03','04','05','06','07','08','09','10',
                                   '11','12','13','14','15','16','17','18','19','20'),
        [string]   $ResultPath = (Join-Path $PSScriptRoot '..\gate-results.json')
    )

    $all = New-Object System.Collections.Generic.List[object]

    foreach ($id in $ScenarioId) {
        Write-Host ""
        Write-Host ("#" * 70)
        Write-Host "# scenario-$id  ($($ScenarioId.IndexOf($id) + 1) of $($ScenarioId.Count))"
        Write-Host ("#" * 70)

        # A scenario carrying INVALID.md is EXCLUDED, not run.
        #
        # "This scenario cannot be induced on the current image" and "this
        # scenario's check is broken" are different states, and running the
        # former produces the latter's output. scenario-01 (Zerologon) reported
        # gate 1 FAILED on every run, which reads as a defect someone should go
        # and fix -- when in fact its check is correct and the vulnerability is
        # simply absent from a Server 2019 build that postdates the February
        # 2021 enforcement. Excluding it says so directly instead of diluting
        # the pass rate with a failure nobody can act on.
        #
        # INVALID.md is required to state the evidence and what restoring the
        # scenario would take; see scenario-01/INVALID.md for the shape.
        $invalidPath = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) "scenario-$id") 'INVALID.md'
        if (Test-Path $invalidPath) {
            $reason = (Select-String -Path $invalidPath -Pattern '^\*\*Status:' -List).Line
            if (-not $reason) { $reason = 'marked INVALID; see INVALID.md' }
            Write-Warning "scenario-$id EXCLUDED -- $reason"
            $r = [pscustomobject]@{
                Scenario   = "scenario-$id"
                Validated  = 'EXCLUDED'
                Gates      = [ordered]@{ excluded_reason = $reason }
                HasFixture = $true
            }
        }
        else {
            try {
                $r = Test-ScenarioGates -ScenarioId $id
            }
            catch {
                Write-Warning "scenario-$id threw: $($_.Exception.Message.Split([char]10)[0])"
                $r = [pscustomobject]@{
                    Scenario   = "scenario-$id"
                    Validated  = $false
                    Gates      = @{ error = $_.Exception.Message.Split([char]10)[0] }
                    HasFixture = $true
                }
            }
        }

        $all.Add($r)

        # Persist after every scenario -- a 90-minute run must not lose
        # everything to one interruption.
        #
        # .ToArray() matters: piping a List[object] into ConvertTo-Json
        # serialises the LIST OBJECT, producing a single record whose
        # properties are arrays rather than an array of records. Reading that
        # back gives one object with Scenario=@('scenario-01','scenario-02'),
        # which prints as System.Object[] and cannot be tabulated per scenario.
        ConvertTo-Json -InputObject $all.ToArray() -Depth 6 |
            Set-Content -LiteralPath $ResultPath -Encoding utf8
    }

    Write-Host ""
    Write-Host ("=" * 70)
    Write-Host "SUMMARY"
    Write-Host ("=" * 70)
    $all | ForEach-Object {
        "{0,-12} validated={1,-6} g1poc={2,-6} g1svc={3,-6} g2={4,-6} g3={5,-6} g4={6}" -f `
            $_.Scenario, $_.Validated, $_.Gates.gate1_poc_fails, $_.Gates.gate1_service_healthy,
            $_.Gates.gate2_solvable, $_.Gates.gate3_sabotage, $_.Gates.gate4_not_restarted
    }
    $ok = @($all | Where-Object { $_.Validated }).Count
    Write-Host ""
    Write-Host "VALIDATED: $ok / $($all.Count)"
    Write-Host "results: $ResultPath"

    return $all
}
