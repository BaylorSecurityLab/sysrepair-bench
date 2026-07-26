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
    param([double] $ToleranceMinutes = 1.0)

    Write-Host '[clock] resyncing corp-dc01 (authoritative)'
    Invoke-Command -VMName 'corp-dc01' -Credential $script:LabCred -ScriptBlock {
        w32tm /resync /force 2>&1 | Out-Null
    } -ErrorAction SilentlyContinue

    foreach ($vm in 'corp-ca01', 'corp-ws01') {
        Write-Host "[clock] resyncing $vm"
        Invoke-Command -VMName $vm -Credential $script:LabCred -ScriptBlock {
            w32tm /resync /force 2>&1 | Out-Null
        } -ErrorAction SilentlyContinue
    }

    Write-Host '[clock] resyncing attacker01'
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes `
        -i (Join-Path $HOME '.ssh\srb_attacker') 'vagrant@10.20.30.10' `
        'sudo chronyc makestep >/dev/null 2>&1 || sudo systemctl restart systemd-timesyncd' 2>&1 | Out-Null

    # --- verify ---
    $results = foreach ($vm in 'corp-dc01', 'corp-ca01', 'corp-ws01') {
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
        [switch] $SkipStart
    )

    if (-not $SkipStart) {
        Write-Host '[boot] starting corp-dc01'
        Start-VM -Name 'corp-dc01' -ErrorAction SilentlyContinue | Out-Null
    }

    $dc = Wait-LabMachineReady -Machine dc -TimeoutSeconds $DcTimeoutSeconds
    if (-not $dc.Ready) {
        throw "Start-LabOrdered: corp-dc01 never became ready (failed probe: $($dc.FailedProbe)). Refusing to start dependent machines."
    }

    if (-not $SkipStart) {
        Write-Host '[boot] starting corp-ca01, corp-ws01, attacker01'
        Start-VM -Name 'corp-ca01', 'corp-ws01', 'attacker01' -ErrorAction SilentlyContinue | Out-Null
    }

    # Members need a few seconds of uptime before PowerShell Direct answers;
    # the clock sync below also needs them running.
    Start-Sleep -Seconds 20
    Sync-LabClocks | Out-Null

    $rest = foreach ($m in 'ca', 'ws', 'attacker') {
        Wait-LabMachineReady -Machine $m -TimeoutSeconds $OtherTimeoutSeconds
    }

    $results = @($dc) + @($rest)
    $failed  = $results | Where-Object { -not $_.Ready }
    if ($failed) {
        throw "Start-LabOrdered: not ready -- $(($failed | ForEach-Object { "$($_.Machine):$($_.FailedProbe)" }) -join ', ')"
    }

    Write-Host '[boot] all four machines ready and clocks verified'
    return $results
}
