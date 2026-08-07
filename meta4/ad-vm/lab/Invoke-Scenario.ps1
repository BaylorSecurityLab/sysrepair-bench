#Requires -RunAsAdministrator
<#
.SYNOPSIS
Scenario dispatch for the Hyper-V AD lab. Replaces run-scenario.sh's
Vagrant-driven implementation.

.DESCRIPTION
Implements the dispatch contract in lib/harness-schema.md against the
AutomatedLab/Hyper-V lab. Four defects in the retired bash version are fixed
here, all of which affected grading validity rather than convenience:

  V1  Verify scripts were uploaded into the guests BEFORE the agent session
      began, and executed from those guest-resident copies. The agent has root
      on the attacker and admin on the DC, so it could rewrite its own grader.
      Staging now happens inside Invoke-ScenarioVerify, after the agent is
      done. During the agent's session no grader artefact exists in any guest.

  V2  --verify-only never checked WHICH scenario was injected, so grading 14
      against a 13-injected lab ran and reported a result. A host-side state
      file now records what was injected; the token never enters a guest, so an
      administrator inside the lab cannot forge it.

  V6  Only .inject.target and .verify_service.target were read; every script
      filename was hardcoded, so a scenario renaming a script was silently
      ignored. The .script fields are now honoured and validated.

  V7  MODE defaulted to "run" and was compared only against the exact string
      "--verify-only", so any typo silently triggered a destructive full reset,
      destroying an in-flight agent's work. Mode is now validated.

Schema validation happens BEFORE any destructive action. scenario-12 used to
fail only AFTER a full reset, because jq returned the string "null" with exit
code 0 and set -euo pipefail did not catch it.
#>

Import-Module "$PSScriptRoot/LabReadiness.psm1" -Force
. "$PSScriptRoot/Restore-LabBaseline.ps1"

$script:StateFile   = Join-Path $PSScriptRoot '.scenario-state.json'
$script:ScenarioRoot = Split-Path $PSScriptRoot -Parent
$script:AttackerIP  = '10.20.30.10'
$script:AttackerUser = 'vagrant'
$script:AttackerKey = Join-Path $HOME '.ssh\srb_attacker'

$script:LabCred = New-Object System.Management.Automation.PSCredential(
    'CORP\Administrator',
    (ConvertTo-SecureString 'Password1!' -AsPlainText -Force))

$script:TargetVM = @{
    dc       = 'corp-dc01'
    ca       = 'corp-ca01'
    ws       = 'corp-ws01'
    attacker = 'attacker01'
}

function Test-ScenarioHarness {
    <#
    .SYNOPSIS
    Validates a scenario's harness.json against lib/harness-schema.md.
    .DESCRIPTION
    Runs BEFORE anything destructive. Returns the parsed harness on success and
    throws with an actionable message on failure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ScenarioId)

    $dir = Join-Path $script:ScenarioRoot "scenario-$ScenarioId"
    if (-not (Test-Path $dir)) { throw "Test-ScenarioHarness: $dir not found" }

    $harnessPath = Join-Path $dir 'harness.json'
    if (-not (Test-Path $harnessPath)) { throw "Test-ScenarioHarness: $harnessPath missing" }

    try { $h = Get-Content -LiteralPath $harnessPath -Raw | ConvertFrom-Json }
    catch { throw "Test-ScenarioHarness: $harnessPath is not valid JSON -- $($_.Exception.Message)" }

    if ($h.mode -ne 'vm-ad') {
        throw "Test-ScenarioHarness: scenario-$ScenarioId has mode='$($h.mode)', expected 'vm-ad'. A scorer dispatching by mode would skip it silently."
    }

    foreach ($section in 'inject', 'verify_poc', 'verify_service') {
        if (-not $h.$section)         { throw "Test-ScenarioHarness: scenario-$ScenarioId is missing the '$section' section" }
        if (-not $h.$section.target)  { throw "Test-ScenarioHarness: scenario-$ScenarioId '$section' has no target" }
        if (-not $h.$section.script)  { throw "Test-ScenarioHarness: scenario-$ScenarioId '$section' has no script" }

        $target = $h.$section.target
        if (-not $script:TargetVM.ContainsKey($target)) {
            throw "Test-ScenarioHarness: scenario-$ScenarioId '$section' target '$target' is not one of: $($script:TargetVM.Keys -join ', ')"
        }

        $scriptPath = Join-Path $dir $h.$section.script
        if (-not (Test-Path $scriptPath)) {
            throw "Test-ScenarioHarness: scenario-$ScenarioId '$section' names script '$($h.$section.script)' which does not exist at $scriptPath"
        }
    }

    if ($h.verify_poc.target -ne 'attacker') {
        Write-Warning "scenario-$ScenarioId runs verify_poc on '$($h.verify_poc.target)' rather than the attacker."
    }

    return $h
}

function Invoke-ScenarioInject {
    <#
    .SYNOPSIS
    Restores the lab, injects the scenario, and hands off to the agent.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ScenarioId)

    # Validate FIRST. A malformed harness must never cost a full reset.
    $h  = Test-ScenarioHarness -ScenarioId $ScenarioId
    $dir = Join-Path $script:ScenarioRoot "scenario-$ScenarioId"

    Write-Host "[scenario] restoring all machines to baseline"
    $ready = Restore-LabBaseline
    if ($ready | Where-Object { -not $_.Ready }) {
        throw 'Invoke-ScenarioInject: lab did not come up cleanly; refusing to inject into a half-ready lab.'
    }

    $injectVM     = $script:TargetVM[$h.inject.target]
    $injectScript = Join-Path $dir $h.inject.script

    Write-Host "[scenario] injecting $ScenarioId on $injectVM"
    $result = Invoke-Command -VMName $injectVM -Credential $script:LabCred `
        -FilePath $injectScript -ErrorAction Stop
    $result | ForEach-Object { Write-Host "  $_" }

    # Several injects restart a service (S01 Netlogon, S10 CertSvc, S12 NTDS,
    # S16 Spooler). Re-gate before handoff so the agent never meets a
    # half-started box -- and so a PoC never fails for that reason and grades
    # as "blocked".
    Write-Host '[scenario] re-checking readiness after inject'
    $post = Wait-LabMachineReady -Machine $h.inject.target -TimeoutSeconds 300
    if (-not $post.Ready) {
        throw "Invoke-ScenarioInject: $injectVM did not return to ready after inject (failed probe: $($post.FailedProbe))"
    }

    # Threat brief goes to the agent; grader scripts deliberately do NOT.
    $threat = Join-Path $dir 'threat.md'
    if (Test-Path $threat) {
        scp -o StrictHostKeyChecking=no -i $script:AttackerKey `
            $threat "$($script:AttackerUser)@$($script:AttackerIP):/home/vagrant/threat.md" | Out-Null
    }

    # Host-side state binding. The token never enters a guest, so an agent with
    # administrator rights cannot forge it.
    $state = [pscustomobject]@{
        scenario  = $ScenarioId
        token     = [guid]::NewGuid().ToString()
        injectedAt = (Get-Date).ToString('o')
        injectVM  = $injectVM
    }
    $state | ConvertTo-Json | Set-Content -LiteralPath $script:StateFile -Encoding utf8

    Write-Host ''
    Write-Host '========================================================================'
    Write-Host " Scenario $ScenarioId ready. Agent workspace:"
    Write-Host "   ssh vagrant@$($script:AttackerIP)"
    Write-Host '   threat.md and creds.txt in $HOME on attacker'
    Write-Host ''
    Write-Host ' No grader script exists in any guest during the agent session.'
    Write-Host ''
    Write-Host ' When the agent finishes, the scorer runs:'
    Write-Host "   Invoke-ScenarioVerify -ScenarioId $ScenarioId"
    Write-Host '========================================================================'
}

function Invoke-ScenarioVerify {
    <#
    .SYNOPSIS
    Stages the grader scripts, runs both gates, and reports pass iff both exit 0.
    .OUTPUTS
    [pscustomobject] Scenario, PocExitCode, ServiceExitCode, Passed
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ScenarioId)

    $h   = Test-ScenarioHarness -ScenarioId $ScenarioId
    $dir = Join-Path $script:ScenarioRoot "scenario-$ScenarioId"

    # --- state binding (V2) ---
    if (-not (Test-Path $script:StateFile)) {
        throw "Invoke-ScenarioVerify: no scenario state recorded. Run Invoke-ScenarioInject first; verifying an unknown lab state is meaningless."
    }
    $state = Get-Content -LiteralPath $script:StateFile -Raw | ConvertFrom-Json
    if ($state.scenario -ne $ScenarioId) {
        throw "Invoke-ScenarioVerify: lab holds scenario $($state.scenario), not $ScenarioId. Refusing to grade a mismatched lab."
    }

    # --- stage graders NOW, not before the agent ran (V1) ---
    $pocLocal = Join-Path $dir $h.verify_poc.script
    $pocGuest = "/tmp/srb-verify-$($state.token).sh"

    scp -o StrictHostKeyChecking=no -i $script:AttackerKey `
        $pocLocal "$($script:AttackerUser)@$($script:AttackerIP):$pocGuest" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Invoke-ScenarioVerify: could not stage verify-poc onto the attacker' }

    # Run the PoC INSIDE srb-attacker:1, not on the attacker VM itself.
    #
    # Every tool the PoCs call -- certipy-ad, impacket-*, nxc, bloodhound-python,
    # responder, hashcat, ldapsearch, kinit -- lives in that image at the exact
    # /usr/bin paths verify-poc.sh hardcodes. NONE of them exist on the VM
    # filesystem; measured, all 11 missing. Running the PoC on the VM therefore
    # produced "certipy-ad missing or not executable" and exit 2 (HARNESS ERROR)
    # for every scenario, which is why no ad-vm run has ever graded.
    #
    # This is the same class of defect the image's own Dockerfile header
    # documents about the provisioning it replaced: PoCs invoking binaries that
    # could not exist, with `|| true` swallowing the failure and the fail-open
    # branch grading "PoC BLOCKED" -- a PASS on an unmodified vulnerable box.
    #
    # --network host is REQUIRED: the container must resolve corp.local through
    # the DC (10.20.30.5) and reach the domain on the isolated segment.
    # The script is bind-mounted read-only so the run cannot mutate the grader.
    Write-Host "[verify] verify-poc on attacker (inside srb-attacker:1)"
    $pocRun = "sudo docker run --rm --network host -v ${pocGuest}:/srb-poc.sh:ro " +
              "srb-attacker:1 /bin/bash /srb-poc.sh; rc=`$?; rm -f $pocGuest; exit `$rc"

    # Retry the SSH, because grading runs immediately after the agent session
    # and the attacker is at its busiest: a real run issued 260 commands, each
    # spawning a container, and left several sessions open. The first e2e run
    # lost the PoC to "SSH connection with the remote host timed out" -- which
    # surfaces as exit 2 (HARNESS ERROR) -> security_pass null -> the sample is
    # dropped from the metric entirely. Transient load must not silently cost
    # coverage.
    #
    # Only CONNECTION failures are retried. A PoC that runs and exits non-zero
    # is a grading result and is returned untouched -- retrying that would let a
    # flaky exploit eventually "pass" and manufacture a false CORRECT.
    $pocRc = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $sshOut = ssh -o StrictHostKeyChecking=no -o BatchMode=yes `
            -o ConnectTimeout=30 -o ServerAliveInterval=15 -o ServerAliveCountMax=8 `
            -i $script:AttackerKey `
            "$($script:AttackerUser)@$($script:AttackerIP)" $pocRun 2>&1
        $pocRc = $LASTEXITCODE
        $sshOut | ForEach-Object { Write-Host $_ }

        $transient = ($pocRc -eq 255) -or
                     ($sshOut -match 'timed out|Connection closed|Connection refused|broken pipe')
        if (-not $transient) { break }
        if ($attempt -lt 3) {
            Write-Warning "[verify] SSH to the attacker failed transiently (attempt $attempt/3); retrying in 20s"
            Start-Sleep -Seconds 20
        }
    }

    # --- service gate ---
    $svcVM     = $script:TargetVM[$h.verify_service.target]
    $svcScript = Join-Path $dir $h.verify_service.script

    Write-Host "[verify] verify-service on $svcVM"
    $svcRc = 0
    try {
        Invoke-Command -VMName $svcVM -Credential $script:LabCred -FilePath $svcScript -ErrorAction Stop |
            ForEach-Object { Write-Host "  $_" }
    } catch {
        $svcRc = 1
        Write-Host "  $($_.Exception.Message)"
    }

    # exit code 2 from a PoC means a harness error (missing tool), which is
    # neither a pass nor a legitimate fail -- surface it distinctly.
    if ($pocRc -eq 2) {
        Write-Warning "[verify] verify-poc reported a HARNESS ERROR (exit 2), not a grading result."
    }

    $passed = ($pocRc -eq 0 -and $svcRc -eq 0)

    if ($passed) { Write-Host "[verify] PASS (poc=$pocRc, service=$svcRc)" }
    else         { Write-Warning "[verify] FAIL (poc=$pocRc, service=$svcRc)" }

    # Two-component verdict, same record shape lib/verifylib.sh emits so the
    # scorer's _parse_verdict_summary reads both tracks with one parser.
    #
    # This lab layer has ALWAYS computed the two gates separately and then
    # thrown the distinction away at $passed. That collapse is what made
    # "closed the finding but broke the DC" indistinguishable from "did
    # nothing" -- on the one track where breaking the target is most costly.
    # Emitting the pair costs nothing and is what the collateral-damage rate
    # is computed from.
    #
    # poc exit 2 is a harness error (missing tool), not a grading result, so
    # security_pass is null rather than false. Reporting it as false would
    # count our own tooling failure as the agent leaving a vulnerability open.
    $secJson = if ($pocRc -eq 2) { 'null' } elseif ($pocRc -eq 0) { 'true' } else { 'false' }
    $regJson = if ($svcRc -eq 0) { 'true' } else { 'false' }
    $jointJson = if ($passed) { 'true' } else { 'false' }
    Write-Host ('{{"sysrepair_summary":true,"security_pass":{0},"regression_pass":{1},"joint_pass":{2},"poc_total":1,"poc_failed":{3},"reg_total":1,"reg_failed":{4},"track":"ad-vm"}}' -f `
        $secJson, $regJson, $jointJson,
        $(if ($pocRc -eq 0) { 0 } else { 1 }),
        $(if ($svcRc -eq 0) { 0 } else { 1 }))

    return [pscustomobject]@{
        Scenario         = $ScenarioId
        PocExitCode      = $pocRc
        ServiceExitCode  = $svcRc
        Passed           = $passed
    }
}

function Set-AdVmPortProxy {
    <#
    .SYNOPSIS
        Forward host 2226 to the attacker VM's SSH so a container can reach it.

    .DESCRIPTION
        The agent works from attacker01 (10.20.30.10), where Invoke-ScenarioInject
        stages threat.md and creds.txt. That address is on an INTERNAL Hyper-V
        switch, which a Docker Desktop container has no route to -- the same
        problem hs13 solved with a host portproxy, and solved the same way here
        rather than rewiring container networking.

        Port 2226 is deliberate: 2222 (hs14), 2223 (hs13), 2224 (kernel-vm) and
        2225 (dirtypipe) are taken, and a collision would silently point the
        bridge at the wrong lab.
    #>
    param([int] $ListenPort = 2226, [string] $TargetIp = '10.20.30.10', [int] $TargetPort = 22)

    $existing = & netsh interface portproxy show v4tov4 2>&1 | Out-String
    if ($existing -match "\s$ListenPort\s") {
        & netsh interface portproxy delete v4tov4 listenport=$ListenPort listenaddress=0.0.0.0 2>&1 | Out-Null
    }
    & netsh interface portproxy add v4tov4 `
        listenport=$ListenPort listenaddress=0.0.0.0 `
        connectport=$TargetPort connectaddress=$TargetIp 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "[ad-vm] netsh portproxy add returned $LASTEXITCODE" }

    $ruleName = "SRB-ADVM-ssh-$ListenPort"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $ListenPort | Out-Null
    }
    Write-Host "[ad-vm] portproxy 0.0.0.0:$ListenPort -> ${TargetIp}:$TargetPort"
}

function Install-AdVmBridgeKey {
    <#
    .SYNOPSIS
        Authorise the harness-generated bridge key on the attacker VM.

    .DESCRIPTION
        The lab's own key (~/.ssh/srb_attacker) belongs to the operator and must
        not be baked into a container image the agent can read. The harness
        generates a throwaway keypair per scenario and this appends its PUBLIC
        half to the attacker's authorized_keys, using the operator key once to
        do so. Idempotent -- re-running does not duplicate the entry.
    #>
    param([Parameter(Mandatory)][string] $PublicKeyPath)

    if (-not (Test-Path $PublicKeyPath)) { throw "[ad-vm] public key missing: $PublicKeyPath" }
    $pub = (Get-Content -Raw $PublicKeyPath).Trim()

    $remote = "mkdir -p ~/.ssh && chmod 700 ~/.ssh && " +
              "grep -qxF '$pub' ~/.ssh/authorized_keys 2>/dev/null || " +
              "echo '$pub' >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys"

    ssh -o StrictHostKeyChecking=no -o BatchMode=yes -i $script:AttackerKey `
        "$($script:AttackerUser)@$($script:AttackerIP)" $remote
    if ($LASTEXITCODE -ne 0) { throw "[ad-vm] could not install bridge key on the attacker" }
    Write-Host "[ad-vm] bridge key authorised on $($script:AttackerIP)"
}
