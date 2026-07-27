#Requires -RunAsAdministrator

Import-Module "$PSScriptRoot/LabReadiness.psm1" -Force

$script:LabCred = New-Object System.Management.Automation.PSCredential(
    'CORP\Administrator',
    (ConvertTo-SecureString 'Password1!' -AsPlainText -Force))

function Sync-LabClocks {
    <#
    .SYNOPSIS
    Resynchronises every guest clock against the DC and VERIFIES the result.

    .DESCRIPTION
    A restored cold checkpoint is by definition stale. Kerberos rejects
    authentication beyond roughly five minutes of skew, and a Kerberos failure
    inside a PoC is indistinguishable from the vulnerability having been fixed
    -- so skew produces false PASSes.

    The resync is VERIFIED, not merely issued. The first draft piped w32tm
    output to Out-Null and never checked anything, which would have reported
    success even if every resync failed.

    .OUTPUTS
    [pscustomobject[]] Machine, SkewMinutes, InTolerance
    #>
    [CmdletBinding()]
    param(
        [double]   $ToleranceMinutes = 1.0,
        [string[]] $Machines = @('ca', 'ws'),
        [switch]   $IncludeAttacker
    )

    $map = @{ ca = 'corp-ca01'; ws = 'corp-ws01' }
    $windowsMembers = @($Machines | Where-Object { $map.ContainsKey($_) } | ForEach-Object { $map[$_] })

    Write-Host '[clock] resyncing corp-dc01 (authoritative)'
    Invoke-Command -VMName 'corp-dc01' -Credential $script:LabCred -ScriptBlock {
        w32tm /resync /force 2>&1 | Out-Null
    } -ErrorAction SilentlyContinue

    foreach ($vm in $windowsMembers) {
        Write-Host "[clock] resyncing $vm"
        Invoke-Command -VMName $vm -Credential $script:LabCred -ScriptBlock {
            w32tm /resync /force 2>&1 | Out-Null
        } -ErrorAction SilentlyContinue
    }

    if ($IncludeAttacker) {
        Write-Host '[clock] resyncing attacker01'
        ssh -o StrictHostKeyChecking=no -o BatchMode=yes `
            -i (Join-Path $HOME '.ssh\srb_attacker') 'vagrant@10.20.30.10' `
            'sudo chronyc makestep >/dev/null 2>&1 || sudo systemctl restart systemd-timesyncd' 2>&1 | Out-Null
    }

    # --- verify ---
    #
    # An UNREADABLE clock is a different fault from a SKEWED one and must not
    # be reported as skew. The first version computed NaN when the guest could
    # not be reached, and `NaN -le tolerance` is false, so it threw "clock skew
    # outside 1 min -- corp-ws01=NaNmin" when the actual problem was that
    # PowerShell Direct returned nothing. That misdiagnosis aborted a
    # diagnostic run.
    #
    # Reading a just-booted guest can also fail transiently, so retry before
    # concluding anything.
    $results = foreach ($vm in (@('corp-dc01') + $windowsMembers)) {
        $guestUtc = $null
        for ($attempt = 1; $attempt -le 3 -and -not $guestUtc; $attempt++) {
            try {
                $guestUtc = Invoke-Command -VMName $vm -Credential $script:LabCred -ScriptBlock {
                    [datetime]::UtcNow
                } -ErrorAction Stop
            } catch {
                if ($attempt -lt 3) { Start-Sleep -Seconds 10 }
            }
        }

        if ($guestUtc) {
            $skew = [math]::Abs(($guestUtc - [datetime]::UtcNow).TotalMinutes)
            [pscustomobject]@{
                Machine     = $vm
                SkewMinutes = [math]::Round($skew, 2)
                Readable    = $true
                InTolerance = ($skew -le $ToleranceMinutes)
            }
        }
        else {
            [pscustomobject]@{
                Machine     = $vm
                SkewMinutes = $null
                Readable    = $false
                InTolerance = $false
            }
        }
    }

    $unreadable = @($results | Where-Object { -not $_.Readable })
    $skewed     = @($results | Where-Object { $_.Readable -and -not $_.InTolerance })

    if ($unreadable) {
        throw "Sync-LabClocks: could not read the clock on $(($unreadable.Machine) -join ', ') after 3 attempts. This is a REACHABILITY failure, not clock skew -- PowerShell Direct returned nothing."
    }
    if ($skewed) {
        throw "Sync-LabClocks: clock skew outside $ToleranceMinutes min after resync -- $(($skewed | ForEach-Object { "$($_.Machine)=$($_.SkewMinutes)min" }) -join ', '). Kerberos will fail and PoCs will grade as false passes."
    }

    Write-Host "[clock] all guests within $ToleranceMinutes min of host UTC"
    return $results
}

function Start-LabOrdered {
    <#
    .SYNOPSIS
    Cold-starts the lab in dependency order, gating each machine on readiness.

    .DESCRIPTION
    corp-dc01 starts first and MUST reach ready before anything else starts.
    corp-ca01 is domain-joined and an Enterprise CA's CertSvc requires the DC
    for DNS and Kerberos at startup -- booted alongside the DC it can fail to
    start outright, which silently breaks scenarios 07-11.

    ORDERING NOTE: clocks are synchronised immediately after the DC is ready
    and BEFORE the member probes run. The member probes call
    Test-ComputerSecureChannel, which is Kerberos-dependent, so a large skew
    would fail those probes and abort the run before the clock fix ever
    executed -- sequencing the remedy behind the symptom it treats.

    .OUTPUTS
    [pscustomobject[]] one readiness record per machine
    #>
    [CmdletBinding()]
    param(
        [int]    $DcTimeoutSeconds    = 900,
        [int]    $OtherTimeoutSeconds = 600,
        [switch] $SkipStart,

        # Which non-DC machines to bring up. Defaults to the full lab; narrow it
        # during bring-up, when attacker01 has not been built yet. corp-dc01 is
        # always included -- nothing else can be ready without it.
        [ValidateSet('ca', 'ws', 'attacker')]
        [string[]] $Members = @('ca', 'ws', 'attacker')
    )

    if (-not $SkipStart) {
        Write-Host '[boot] starting corp-dc01'
        Start-VM -Name 'corp-dc01' -ErrorAction SilentlyContinue | Out-Null
    }

    $dc = Wait-LabMachineReady -Machine dc -TimeoutSeconds $DcTimeoutSeconds
    if (-not $dc.Ready) {
        throw "Start-LabOrdered: corp-dc01 never became ready (failed probe: $($dc.FailedProbe)). Refusing to start dependent machines."
    }

    $memberVMs = @{ ca = 'corp-ca01'; ws = 'corp-ws01'; attacker = 'attacker01' }

    if (-not $SkipStart -and $Members) {
        $names = @($Members | ForEach-Object { $memberVMs[$_] })
        Write-Host "[boot] starting $($names -join ', ')"

        # Start each VM individually and REPORT failures.
        #
        # `Start-VM -ErrorAction SilentlyContinue` hides the most common
        # real-world failure on a single-host lab: not enough free RAM. The VM
        # stays Off, the readiness probe times out, and the run reports a
        # readiness or clock problem -- pointing at entirely the wrong
        # subsystem. Observed here: corp-ws01 and attacker01 silently failed to
        # start with 1.2 GB free, and the visible symptom was
        # "could not read the clock on corp-ws01".
        $failedToStart = @()
        foreach ($n in $names) {
            $vm = Get-VM -Name $n -ErrorAction SilentlyContinue
            if (-not $vm) { $failedToStart += "$n (not found)"; continue }
            if ($vm.State -eq 'Running') { continue }
            try { Start-VM -Name $n -ErrorAction Stop | Out-Null }
            catch { $failedToStart += "$n ($($_.Exception.Message.Split([char]10)[0]))" }
        }

        if ($failedToStart) {
            $os   = Get-CimInstance Win32_OperatingSystem
            $freeGb = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
            $need = 0
            foreach ($n in $names) {
                $m = Get-VMMemory -VMName $n -ErrorAction SilentlyContinue
                if ($m -and (Get-VM -Name $n).State -ne 'Running') { $need += $m.Startup }
            }
            $needGb = [math]::Round($need / 1GB, 1)

            $hogs = (Get-Process | Sort-Object WorkingSet64 -Descending |
                     Select-Object -First 3 |
                     ForEach-Object { "$($_.ProcessName) $([math]::Round($_.WorkingSet64/1GB,1))GB" }) -join ', '

            throw @"
Start-LabOrdered: VM(s) failed to start: $($failedToStart -join '; ')

Host has ${freeGb} GB free; these VMs need about ${needGb} GB to start.
Largest processes: $hogs

This is a host memory constraint, not a lab fault. Close memory-heavy
applications, or run the lab with fewer machines via -Members.
"@
        }
    }

    # Members need a few seconds of uptime before PowerShell Direct answers;
    # the clock sync below also needs them running.
    Start-Sleep -Seconds 20
    Sync-LabClocks -Machines ($Members | Where-Object { $_ -in 'ca', 'ws' }) | Out-Null

    # 'ws' before 'ca': the CA probe checks the RPC endpoint FROM corp-ws01,
    # because the CA cannot detect its own unreachability (see Test-CaReady).
    # Probing in the caller's order would ask ws01 a question before ws01 was
    # up and score the CA unreachable on the strength of the wrong machine.
    $ordered = @($Members | Where-Object { $_ -eq 'ws' }) +
               @($Members | Where-Object { $_ -ne 'ws' })

    $rest = foreach ($m in $ordered) {
        Wait-LabMachineReady -Machine $m -TimeoutSeconds $OtherTimeoutSeconds
    }

    # CertSvc registers its RPC endpoints once, at service start. Resuming a
    # snapshot can bring it up before the network is ready, leaving it bound to
    # ncalrpc only -- healthy to every local check, invisible to every remote
    # one. Waiting cannot fix that; only a restart re-registers. Retry once,
    # then let the throw below report it.
    $caResult = $rest | Where-Object { $_.Machine -eq 'ca' }
    if ($caResult -and -not $caResult.Ready -and $caResult.FailedProbe -eq 'ca-rpc-endpoint') {
        Write-Warning '[boot] CA is up locally but has no TCP RPC endpoint; restarting CertSvc'
        if (Repair-CaRpcEndpoint) {
            $rest = @($rest | Where-Object { $_.Machine -ne 'ca' }) +
                    @(Wait-LabMachineReady -Machine ca -TimeoutSeconds $OtherTimeoutSeconds)
        }
    }

    $results = @($dc) + @($rest)
    $failed  = $results | Where-Object { -not $_.Ready }
    if ($failed) {
        throw "Start-LabOrdered: not ready -- $(($failed | ForEach-Object { "$($_.Machine):$($_.FailedProbe)" }) -join ', ')"
    }

    Write-Host "[boot] all $($results.Count) machine(s) ready and clocks verified"
    return $results
}
