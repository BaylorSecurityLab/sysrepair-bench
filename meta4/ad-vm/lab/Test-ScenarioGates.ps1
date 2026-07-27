#Requires -RunAsAdministrator
<#
.SYNOPSIS
Runs a scenario through the four proof gates from the verify-check hardening
methodology, plus the negative control the benchmark currently lacks.

.DESCRIPTION
A green run proves nothing on its own -- the broken checks were green too. This
harness is what turns "the scenario passed" into evidence.

THE GATES, translated to the AD harness:

  1. BASELINE FAILS FOR THE RIGHT REASON
     Restore, inject, run nothing else. The PoC gate must FAIL (exit 1),
     because the vulnerability is present and the attack works. It must fail
     with a real attack result, NOT exit 2 -- exit 2 is this harness's signal
     for "grader tool missing or broken", which is a harness error rather than
     evidence of anything. The service gate must PASS: the box is vulnerable,
     not broken.

  2. STILL SOLVABLE
     Apply reference-fix.ps1. Both gates must now PASS. If a stronger check
     breaks the reference fix, the FIX was wrong -- never weaken the check to
     accommodate it.

  3. SABOTAGE
     Re-apply inject on top of the fix. The PoC gate must FAIL again. A check
     you cannot make fail on demand is not a check.

  4. NOT-RESTARTED
     Apply the fix WITHOUT restarting the affected service. The gates must
     still FAIL. This is the gate that catches config-only checks -- a check
     that greps a config file and never touches the running service passes
     here when it should not.
     Only meaningful where the remediation involves a service; scenarios whose
     fix is a pure directory ACL change legitimately skip it, and skipping is
     recorded rather than silently treated as a pass.

Every gate is reported. A scenario is validated only when gates 1-3 hold and
gate 4 either holds or is explicitly not applicable.

.EXAMPLE
Test-ScenarioGates -ScenarioId 13 -Verbose
Test-ScenarioGates -ScenarioId 06 -SkipRestore   # faster, reuses lab state
#>

Import-Module "$PSScriptRoot/LabReadiness.psm1" -Force
. "$PSScriptRoot/Restore-LabBaseline.ps1"

$script:GateCred = New-Object System.Management.Automation.PSCredential(
    'CORP\Administrator',
    (ConvertTo-SecureString 'Password1!' -AsPlainText -Force))

$script:GateVM = @{ dc = 'corp-dc01'; ca = 'corp-ca01'; ws = 'corp-ws01' }
$script:AttackerIP  = '10.20.30.10'
$script:AttackerKey = Join-Path $HOME '.ssh\srb_attacker'

function Invoke-GuestScript {
    param([string] $Target, [string] $ScriptPath)
    $vm = $script:GateVM[$Target]
    try {
        Invoke-Command -VMName $vm -Credential $script:GateCred -FilePath $ScriptPath -ErrorAction Stop | Out-Null
        return 0
    } catch { return 1 }
}

function Invoke-PocGate {
    <#
    .SYNOPSIS
    Stages and runs verify-poc.sh on the attacker, returning its exit code.
    .DESCRIPTION
    Staged at run time and removed afterwards, never before the agent's
    session -- the agent has root on this box and could otherwise rewrite its
    own grader.

    Exit code meanings, which the gates depend on:
      0  PoC blocked   (remediated)
      1  PoC succeeded (vulnerable) or inconclusive
      2  HARNESS ERROR (grader tool missing/broken) -- never evidence
    #>
    param([string] $ScenarioDir)

    $local = Join-Path $ScenarioDir 'verify-poc.sh'
    $guest = "/tmp/srb-gate-$([guid]::NewGuid().ToString('N')).sh"

    scp -o StrictHostKeyChecking=no -o BatchMode=yes -i $script:AttackerKey `
        $local "vagrant@$($script:AttackerIP):$guest" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { return 2 }

    # RUN INSIDE THE TOOLING CONTAINER, not on the VM host.
    #
    # The attacker VM is a bare Ubuntu cloud image: impacket, certipy, nmap and
    # the rest live ONLY in srb-attacker:1. Running the PoC on the host means
    # every tool is missing, the script falls through to its "unrecognised
    # result" branch, and exits 1 -- which this harness would read as "the
    # attack succeeded", passing gate 1 for entirely the wrong reason.
    #
    # That is the same missing-tool false signal the scenarios themselves had,
    # reproduced in the validator. Observed on scenario-06: gate 1 reported
    # poc=1 with no impacket present at all.
    #
    # --dns is required because the daemon-level DNS pin was removed (it broke
    # image builds); the container gets the DC's resolver per-run instead.
    $runner = "sudo docker run --rm --network host --dns 10.20.30.5 --dns-search corp.local " +
              "-v ${guest}:/verify-poc.sh srb-attacker:1 bash /verify-poc.sh"

    # CAPTURE the output rather than discarding it. A gate failure is only
    # actionable if you can see what the tool actually said -- the recurring
    # defect in this suite is a denial the PoC does not recognise (scenario-06
    # returned "ERROR_DS_DRA_BAD_DN", which matched no denial pattern, so a
    # correct fix graded as failure). Throwing the output away means every
    # such failure costs a manual re-run at several minutes each.
    $out = ssh -o StrictHostKeyChecking=no -o BatchMode=yes -i $script:AttackerKey `
        "vagrant@$($script:AttackerIP)" "$runner 2>&1; rc=`$?; rm -f $guest; exit `$rc" 2>&1 | Out-String

    $script:LastPocOutput = $out
    return $LASTEXITCODE
}

function Test-ScenarioGates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidatePattern('^\d{2}$')] [string] $ScenarioId,
        [switch] $SkipRestore,

        # Upper bound on how long a remediation may take to become observable
        # from the attacker. Polled, not slept -- see gate 2.
        [int] $FixSettleSeconds = 90
    )

    $root = Split-Path $PSScriptRoot -Parent
    $dir  = Join-Path $root "scenario-$ScenarioId"
    if (-not (Test-Path $dir)) { throw "Test-ScenarioGates: $dir not found" }

    $h = Get-Content (Join-Path $dir 'harness.json') -Raw | ConvertFrom-Json
    $injectTarget  = $h.inject.target
    $serviceTarget = $h.verify_service.target
    $injectScript  = Join-Path $dir $h.inject.script
    $serviceScript = Join-Path $dir $h.verify_service.script
    $fixScript     = Join-Path $dir 'reference-fix.ps1'

    $hasFix = Test-Path $fixScript
    $results = [ordered]@{}

    # ---------- GATE 1: baseline fails for the right reason ----------
    Write-Host "`n=== scenario-$ScenarioId GATE 1: baseline fails for the right reason ==="
    if (-not $SkipRestore) {
        $r = Restore-LabBaseline -VMName corp-dc01,corp-ca01,corp-ws01,attacker01 `
                                 -Members ca,ws,attacker -ErrorAction Stop
        if ($r | Where-Object { -not $_.Ready }) { throw 'lab did not come up clean' }
    }
    Invoke-GuestScript -Target $injectTarget -ScriptPath $injectScript | Out-Null
    Start-Sleep -Seconds 10

    $poc1 = Invoke-PocGate -ScenarioDir $dir
    $poc1Out = $script:LastPocOutput
    $svc1 = Invoke-GuestScript -Target $serviceTarget -ScriptPath $serviceScript

    $results['gate1_poc_fails']       = ($poc1 -eq 1)
    $results['gate1_not_harness_err'] = ($poc1 -ne 2)
    $results['gate1_service_healthy'] = ($svc1 -eq 0)

    # ALWAYS keep the vulnerable-box output, not only when gate 1 fails.
    #
    # Most PoCs here fail closed: their "unrecognised result" branch also exits
    # 1. So poc=1 is ambiguous -- it means EITHER the attack was detected OR
    # the check understood nothing and defaulted. Gate 1 cannot tell those
    # apart from the exit code, and only one of them is evidence.
    #
    # scenario-01 was exactly this: gate 1 "passed" while the check may never
    # have recognised the attack at all, because its patterns matched wording
    # the shipped tester does not emit.
    $results['gate1_output'] = ($poc1Out -split "`n" | Select-Object -Last 25) -join "`n"

    # Flag the ambiguity explicitly so a reviewer does not have to infer it.
    $results['gate1_detected_explicitly'] =
        [bool]($poc1Out -match 'PoC SUCCEEDED|still (works|exploitable|allowed)|still permits|successfully')
    Write-Host "  poc=$poc1 (want 1)  service=$svc1 (want 0)"
    if ($poc1 -eq 2) { Write-Warning '  PoC returned 2 = HARNESS ERROR. Not evidence; fix the tooling first.' }

    # ---------- GATE 2: still solvable ----------
    Write-Host "`n=== scenario-$ScenarioId GATE 2: still solvable ==="
    if (-not $hasFix) {
        Write-Warning "  no reference-fix.ps1 -- gate 2 CANNOT be evaluated"
        $results['gate2_solvable'] = 'NO-FIXTURE'
    }
    else {
        Invoke-GuestScript -Target $injectTarget -ScriptPath $fixScript | Out-Null

        # Re-gate readiness AFTER the fix, exactly as gate 1 does after inject.
        #
        # A remediation can restart a service, and a service being locally
        # responsive is not the same as its remote endpoints being
        # re-registered. Observed on scenarios 07-10: reference-fix-10 restarts
        # CertSvc and polls `certutil -ping` until it answers LOCALLY, yet
        # certipy connecting REMOTELY still got
        #   ept_s_not_registered for 91AE6020-9E3C-11CF-8D7C-00AA00C091BE
        # because the RPC endpoint mapper had not re-advertised ICertRequestD.
        # The PoC then reported an inconclusive connection error and gate 2
        # graded FAIL against a correct fix.
        $postFix = Wait-LabMachineReady -Machine $serviceTarget -TimeoutSeconds 240
        if (-not $postFix.Ready) {
            Write-Warning "  target '$serviceTarget' not ready after the fix (probe: $($postFix.FailedProbe)) -- gate 2 result is unreliable"
        }

        # Directory changes are not instantaneous from the attacker's point of
        # view. Removing alice's replication ACEs took longer than 10 seconds
        # to be reflected on the DRSUAPI path -- the PoC still succeeded at
        # 10s and correctly reported BLOCKED at ~30s, so a fixed short sleep
        # made gate 2 fail against a fix that genuinely worked.
        #
        # Poll for the expected outcome rather than sleeping a fixed duration
        # and checking once; bail out early as soon as it holds.
        $poc2 = 1
        $deadline = (Get-Date).AddSeconds($FixSettleSeconds)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 10
            $poc2 = Invoke-PocGate -ScenarioDir $dir
            if ($poc2 -eq 0) { break }
        }

        $poc2Out = $script:LastPocOutput
        $svc2 = Invoke-GuestScript -Target $serviceTarget -ScriptPath $serviceScript
        $results['gate2_solvable'] = ($poc2 -eq 0 -and $svc2 -eq 0)
        Write-Host "  poc=$poc2 (want 0)  service=$svc2 (want 0)"

        # The single most valuable diagnostic in this whole harness. When a
        # correct fix is applied and the PoC still reports vulnerable, the
        # tool's own words usually name the denial signature the PoC failed to
        # match -- which is the fix, and is otherwise invisible.
        if ($poc2 -ne 0) {
            $results['gate2_output'] = ($poc2Out -split "`n" | Select-Object -Last 25) -join "`n"
            Write-Host '  --- PoC output after fix (denial signature likely here) ---'
            ($poc2Out -split "`n" | Select-Object -Last 12) | ForEach-Object { "    $($_.TrimEnd())" }
        }
    }

    # ---------- GATE 3: sabotage ----------
    Write-Host "`n=== scenario-$ScenarioId GATE 3: sabotage ==="
    if (-not $hasFix) {
        Write-Warning '  skipped: gate 3 only means something after a successful gate 2'
        $results['gate3_sabotage'] = 'NO-FIXTURE'
    }
    else {
        Invoke-GuestScript -Target $injectTarget -ScriptPath $injectScript | Out-Null
        Start-Sleep -Seconds 10
        $poc3 = Invoke-PocGate -ScenarioDir $dir
        $results['gate3_sabotage'] = ($poc3 -eq 1)
        Write-Host "  poc=$poc3 (want 1)"
    }

    # ---------- GATE 4: not-restarted ----------
    Write-Host "`n=== scenario-$ScenarioId GATE 4: not-restarted ==="
    $noRestartFix = Join-Path $dir 'reference-fix-norestart.ps1'
    if (-not (Test-Path $noRestartFix)) {
        Write-Warning '  no reference-fix-norestart.ps1 -- gate 4 not evaluated'
        $results['gate4_not_restarted'] = 'NOT-APPLICABLE-OR-MISSING'
    }
    else {
        Invoke-GuestScript -Target $injectTarget -ScriptPath $noRestartFix | Out-Null
        Start-Sleep -Seconds 5
        $poc4 = Invoke-PocGate -ScenarioDir $dir
        # Config changed but service not restarted: the box is still
        # vulnerable, so the PoC must still succeed.
        $results['gate4_not_restarted'] = ($poc4 -eq 1)
        Write-Host "  poc=$poc4 (want 1 -- config-only fix must NOT pass)"
    }

    # COUNT the failures; do not negate a filtered pipeline.
    #
    # The previous form was:
    #     $validated = -not ($hard | Where-Object { $_ -ne $true })
    # Where-Object emits the offending ELEMENT, so a single failing gate makes
    # the pipeline emit $false -- and `-not $false` is $true. The expression
    # therefore reported Validated=True precisely when a gate had failed,
    # which is the exact failure mode this harness exists to catch. Observed
    # on scenario-06: gate2_solvable=False, Validated=True.
    $hard = @($results['gate1_poc_fails'], $results['gate1_not_harness_err'],
              $results['gate1_service_healthy'], $results['gate2_solvable'],
              $results['gate3_sabotage'])

    # Gate 4 counts WHENEVER IT WAS ACTUALLY EVALUATED.
    #
    # It is excluded when no fixture exists (recorded as
    # NOT-APPLICABLE-OR-MISSING), because a remediation with no service to
    # leave unrestarted cannot fail it. But when the fixture DOES exist and the
    # gate returns $false, the check passed on a config-only fix -- it is
    # reading configuration rather than exercising the running service, which
    # is the single most common defect in this suite.
    #
    # The previous version scored only gates 1-3, so scenarios 12 and 13 were
    # reported Validated=True while failing gate 4 outright. Reporting success
    # that was not earned, in the tool built to detect exactly that.
    if ($results['gate4_not_restarted'] -is [bool]) {
        $hard += $results['gate4_not_restarted']
    }

    $failedCount = @($hard | Where-Object { $_ -isnot [bool] -or -not $_ }).Count
    $validated = ($failedCount -eq 0)

    [pscustomobject]@{
        Scenario  = "scenario-$ScenarioId"
        Validated = $validated
        Gates     = $results
        HasFixture = $hasFix
    }
}

function Get-ScenarioFixtureCoverage {
    <#
    .SYNOPSIS
    Reports which scenarios have the negative-control fixtures the gates need.
    .DESCRIPTION
    Until a scenario has reference-fix.ps1, gates 2 and 3 cannot run at all and
    its score is not publishable -- a passing dual gate means nothing without a
    demonstration that it can also fail.
    #>
    [CmdletBinding()] param()

    $root = Split-Path $PSScriptRoot -Parent
    foreach ($d in (Get-ChildItem -Path $root -Directory -Filter 'scenario-*' | Sort-Object Name)) {
        [pscustomobject]@{
            Scenario      = $d.Name
            ReferenceFix  = Test-Path (Join-Path $d.FullName 'reference-fix.ps1')
            NoRestartFix  = Test-Path (Join-Path $d.FullName 'reference-fix-norestart.ps1')
        }
    }
}
