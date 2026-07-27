<#
.SYNOPSIS
Per-machine readiness probes for the SysRepairBench lab.

.DESCRIPTION
TCP reachability is never treated as readiness. On a cold-booted DC the WinRM
listener binds minutes before NTDS, DNS, KDC and SYSVOL are serving, so a TCP
check reports success while the directory is still starting. Injection then
races AD startup, and because the scenarios' terminal branches fail open, the
resulting failure grades as a false PASS.

Windows probes run over PowerShell Direct (VMBus) rather than the network, so
they work before networking settles and need no host route.
#>

$script:LabCred = New-Object System.Management.Automation.PSCredential(
    'CORP\Administrator',
    (ConvertTo-SecureString 'Password1!' -AsPlainText -Force))

$script:MachineMap = @{
    dc       = 'corp-dc01'
    ca       = 'corp-ca01'
    ws       = 'corp-ws01'
    attacker = 'attacker01'
}

$script:AttackerIP   = '10.20.30.10'
$script:AttackerUser = 'vagrant'
$script:AttackerKey  = Join-Path $HOME '.ssh\srb_attacker'

function Test-DcReady {
    param([string] $VMName)

    Invoke-Command -VMName $VMName -Credential $script:LabCred -ErrorAction Stop -ScriptBlock {
        foreach ($svc in 'NTDS', 'Netlogon', 'DNS', 'KDC') {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if (-not $s -or $s.Status -ne 'Running') { return "service:$svc" }
        }

        try { Import-Module ActiveDirectory -ErrorAction Stop } catch { return 'ad-module' }
        try {
            if ((Get-ADDomain -ErrorAction Stop).DNSRoot -ne 'corp.local') { return 'domain-mismatch' }
        } catch { return 'ad-ws' }

        foreach ($share in 'SYSVOL', 'NETLOGON') {
            if (-not (Get-SmbShare -Name $share -ErrorAction SilentlyContinue)) { return "share:$share" }
        }

        # RID POOL. Hyper-V exposes VM-Generation ID, which VirtualBox does
        # not, so every checkpoint restore triggers an invocation-ID reset and
        # RID-pool invalidation. Get-ADDomain and the SYSVOL share can all pass
        # before a RID pool exists, and any inject that creates an object would
        # then fail with "directory service has exhausted the pool of RIDs".
        #
        # Probed by actually creating and deleting an object rather than by
        # `dcdiag /test:RidManager`: under Invoke-Command, a native command's
        # stderr is wrapped in ErrorRecords, so any incidental stderr noise
        # would pin this probe at 'rid-pool' permanently.
        $probeName = "srb-ridprobe-$PID"
        try {
            New-ADUser -Name $probeName -SamAccountName $probeName `
                -AccountPassword (ConvertTo-SecureString 'Rid!Probe123' -AsPlainText -Force) `
                -Enabled $false -ErrorAction Stop
            Remove-ADUser -Identity $probeName -Confirm:$false -ErrorAction SilentlyContinue
        } catch {
            Remove-ADUser -Identity $probeName -Confirm:$false -ErrorAction SilentlyContinue
            return 'rid-pool'
        }

        return $null
    }
}

function Test-CaReady {
    param([string] $VMName)

    $local = Invoke-Command -VMName $VMName -Credential $script:LabCred -ErrorAction Stop -ScriptBlock {
        $s = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
        if (-not $s -or $s.Status -ne 'Running') { return 'service:CertSvc' }

        certutil -ping | Out-Null
        if ($LASTEXITCODE -ne 0) { return 'certutil-ping' }

        if (-not (Test-ComputerSecureChannel)) { return 'secure-channel' }
        return $null
    }
    if ($local) { return $local }

    # --- REMOTE RPC endpoint, probed from a DIFFERENT machine ---
    #
    # Everything above runs ON the CA, so its certutil -ping goes over local
    # RPC (ncalrpc) and stays green even when the CA is unreachable to every
    # other host in the lab. That blind spot is not hypothetical: on the
    # 2026-07-26 gate run scenarios 07-10 all reported the CA healthy -- one of
    # them by successfully ISSUING a certificate with certreq -- while certipy
    # on the attacker got, for every request:
    #
    #   Failed to resolve dynamic endpoint 91AE6020-9E3C-11CF-8D7C-00AA00C091BE
    #   ept_s_not_registered
    #
    # ept_s_not_registered is the endpoint mapper's own answer, so port 135 was
    # reachable and epmapper simply had no ICertRequestD to hand out: CertSvc
    # had registered ncalrpc but never a TCP endpoint. That is what happens when
    # the service starts before the network stack has settled -- precisely what
    # resuming a snapshot does.
    #
    # Probing from corp-ws01 forces the request through epmapper + ICertRequestD
    # over TCP, which is the exact path the PoCs use, using only in-box tooling.
    try {
        $remote = Invoke-Command -VMName 'corp-ws01' -Credential $script:LabCred -ErrorAction Stop -ScriptBlock {
            certutil -ping -config 'corp-ca01.corp.local\corp-ca01-CA' 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { return 'ca-rpc-endpoint' }
            return $null
        }
    }
    catch {
        # A probe that cannot run is not a probe that passed.
        return "ca-rpc-probe-unavailable:$($_.Exception.Message -replace '\s+', ' ')"
    }
    if ($remote) { return $remote }

    return $null
}

function Repair-CaRpcEndpoint {
    <#
    .SYNOPSIS
        Re-registers the CA's TCP RPC endpoint by restarting CertSvc.

    .DESCRIPTION
        Remedy for the 'ca-rpc-endpoint' condition Test-CaReady detects. When
        CertSvc starts before the network is up it registers only ncalrpc, and
        no amount of waiting makes it advertise a TCP endpoint -- the
        registration happens once, at service start. Restarting the service
        with the network already up is what actually fixes it.

        Deliberately separate from Test-CaReady: a readiness probe that mutates
        the thing it measures cannot be trusted to report what it found.
    #>
    param(
        [string] $VMName = 'corp-ca01',
        [int]    $TimeoutSeconds = 180
    )

    Write-Host '[Repair-CaRpcEndpoint] restarting CertSvc to re-register its TCP endpoint'
    Invoke-Command -VMName $VMName -Credential $script:LabCred -ErrorAction Stop -ScriptBlock {
        Restart-Service CertSvc -Force
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        $probe = Test-CaReady -VMName $VMName
        if (-not $probe) {
            Write-Host '[Repair-CaRpcEndpoint] CA now answers over TCP RPC'
            return $true
        }
    }

    Write-Warning "[Repair-CaRpcEndpoint] CA still not answering over TCP RPC after ${TimeoutSeconds}s"
    return $false
}

function Test-WsReady {
    param([string] $VMName)

    Invoke-Command -VMName $VMName -Credential $script:LabCred -ErrorAction Stop -ScriptBlock {
        if (-not (Test-ComputerSecureChannel)) { return 'secure-channel' }
        if (-not (Resolve-DnsName -Name 'corp.local' -ErrorAction SilentlyContinue)) { return 'dns' }
        return $null
    }
}

function Test-AttackerReady {
    # NOTE: this param block is required. Wait-LabMachineReady invokes every
    # probe as `& $probe -VMName $vmName`; without it the call throws on every
    # poll and the attacker never reports ready.
    param([string] $VMName)

    # SINGLE LINE, deliberately. A multi-line here-string does not survive
    # PowerShell's argument passing to ssh -- the remote command arrives
    # mangled, ssh exits non-zero, and the probe reports 'ssh' even though the
    # port is open and key auth works fine. Keep this on one line.
    #
    # `sudo` is used for docker because group membership added by cloud-init
    # is not guaranteed to be active in every non-interactive session, and a
    # permission error here would masquerade as a docker outage.
    $probe = 'sudo docker ps >/dev/null 2>&1 || { echo docker; exit 0; }; ' +
             'sudo docker run --rm --network host --dns 10.20.30.5 --dns-search corp.local ' +
             'srb-attacker:1 getent hosts corp-dc01.corp.local >/dev/null 2>&1 || { echo container-dns; exit 0; }; ' +
             'echo OK'

    $out = ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=yes `
        -i $script:AttackerKey "$($script:AttackerUser)@$($script:AttackerIP)" $probe 2>&1 | Out-String

    if ($LASTEXITCODE -ne 0) { return "ssh (rc=$LASTEXITCODE): $($out.Trim() -replace '\s+', ' ')" }

    $t = $out.Trim()
    if ($t -eq 'OK') { return $null }
    if ($t) { return $t }
    return 'empty-probe-output'
}

function Wait-LabMachineReady {
    <#
    .SYNOPSIS
    Blocks until a machine is genuinely serving, or the timeout expires.

    .OUTPUTS
    [pscustomobject] Machine, Ready, ElapsedSeconds, FailedProbe

    .NOTES
    ElapsedSeconds is a DOUBLE, not an int. Truncating a 0.4s probe to 0 makes
    the "did the probe actually block?" assertion flaky and meaningless.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('dc', 'ca', 'ws', 'attacker')] [string] $Machine,
        [int] $TimeoutSeconds = 600,
        [int] $PollSeconds = 10
    )

    $vmName = $script:MachineMap[$Machine]
    $probe  = switch ($Machine) {
        'dc'       { ${function:Test-DcReady} }
        'ca'       { ${function:Test-CaReady} }
        'ws'       { ${function:Test-WsReady} }
        'attacker' { ${function:Test-AttackerReady} }
    }

    $sw       = [System.Diagnostics.Stopwatch]::StartNew()
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $last     = 'not-started'

    while ((Get-Date) -lt $deadline) {
        try {
            $last = & $probe -VMName $vmName
            if ($null -eq $last) {
                $sw.Stop()
                Write-Host ("[ready] {0} after {1:N1}s" -f $Machine, $sw.Elapsed.TotalSeconds)
                return [pscustomobject]@{
                    Machine        = $Machine
                    Ready          = $true
                    ElapsedSeconds = $sw.Elapsed.TotalSeconds
                    FailedProbe    = $null
                }
            }
        } catch {
            $last = "unreachable: $($_.Exception.Message -replace '\s+', ' ')"
        }
        Start-Sleep -Seconds $PollSeconds
    }

    $sw.Stop()
    Write-Warning ("[ready] {0} NOT ready after {1:N1}s (last: {2})" -f $Machine, $sw.Elapsed.TotalSeconds, $last)
    return [pscustomobject]@{
        Machine        = $Machine
        Ready          = $false
        ElapsedSeconds = $sw.Elapsed.TotalSeconds
        FailedProbe    = $last
    }
}

Export-ModuleMember -Function Wait-LabMachineReady, Test-DcReady, Test-CaReady, Test-WsReady, Test-AttackerReady, Repair-CaRpcEndpoint
