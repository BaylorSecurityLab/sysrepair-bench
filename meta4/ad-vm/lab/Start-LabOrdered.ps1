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
    $results = foreach ($vm in (@('corp-dc01') + $windowsMembers)) {
        $guestUtc = try {
            Invoke-Command -VMName $vm -Credential $script:LabCred -ScriptBlock {
                [datetime]::UtcNow
            } -ErrorAction Stop
        } catch { $null }

        $skew = if ($guestUtc) { [math]::Abs(($guestUtc - [datetime]::UtcNow).TotalMinutes) } else { [double]::NaN }

        [pscustomobject]@{
            Machine     = $vm
            SkewMinutes = $skew
            InTolerance = ($skew -le $ToleranceMinutes)
        }
    }

    $bad = $results | Where-Object { -not $_.InTolerance }
    if ($bad) {
        throw "Sync-LabClocks: clock skew outside $ToleranceMinutes min after resync -- $(($bad | ForEach-Object { "$($_.Machine)=$([math]::Round($_.SkewMinutes,2))min" }) -join ', '). Kerberos will fail and PoCs will grade as false passes."
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
        $names = $Members | ForEach-Object { $memberVMs[$_] }
        Write-Host "[boot] starting $($names -join ', ')"
        Start-VM -Name $names -ErrorAction SilentlyContinue | Out-Null
    }

    # Members need a few seconds of uptime before PowerShell Direct answers;
    # the clock sync below also needs them running.
    Start-Sleep -Seconds 20
    Sync-LabClocks -Machines ($Members | Where-Object { $_ -in 'ca', 'ws' }) | Out-Null

    $rest = foreach ($m in $Members) {
        Wait-LabMachineReady -Machine $m -TimeoutSeconds $OtherTimeoutSeconds
    }

    $results = @($dc) + @($rest)
    $failed  = $results | Where-Object { -not $_.Ready }
    if ($failed) {
        throw "Start-LabOrdered: not ready -- $(($failed | ForEach-Object { "$($_.Machine):$($_.FailedProbe)" }) -join ', ')"
    }

    Write-Host "[boot] all $($results.Count) machine(s) ready and clocks verified"
    return $results
}
