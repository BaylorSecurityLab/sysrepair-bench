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

    ssh -o StrictHostKeyChecking=no -o BatchMode=yes -i $script:AttackerKey `
        "vagrant@$($script:AttackerIP)" "$runner >/dev/null 2>&1; rc=`$?; rm -f $guest; exit `$rc" 2>&1 | Out-Null
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
    $svc1 = Invoke-GuestScript -Target $serviceTarget -ScriptPath $serviceScript

    $results['gate1_poc_fails']       = ($poc1 -eq 1)
    $results['gate1_not_harness_err'] = ($poc1 -ne 2)
    $results['gate1_service_healthy'] = ($svc1 -eq 0)
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

        $svc2 = Invoke-GuestScript -Target $serviceTarget -ScriptPath $serviceScript
        $results['gate2_solvable'] = ($poc2 -eq 0 -and $svc2 -eq 0)
        Write-Host "  poc=$poc2 (want 0)  service=$svc2 (want 0)"
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
