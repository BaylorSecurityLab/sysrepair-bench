#Requires -RunAsAdministrator
<#
.SYNOPSIS
Profile-driven runtime ops shared by the Hyper-V kernel VMs.

.DESCRIPTION
meta4/kernel-vm and meta4/dirtypipe-vm differ only in VM name, guest address, SSH
port, key, and expected kernel. Everything else -- restore, start, port proxy, ABI
assertion, scenario staging, scenario grading -- was duplicated. This is that
logic once, taking a profile:

    @{ VmName='meta4-kernel'; GuestUser='vagrant'; GuestIp='10.20.40.5'
       SshPort=2224; KeyPath='...\srb_kernel'; KernelSeries='5.15.0'; ExpectAbi=25 }

Each VM's *Ops.ps1 keeps its public function names (Initialize-KernelHost,
Test-KernelAbi, ...) because run.py resolves them by name out of lab/hyperv.json.

Two PowerShell traps are handled here so neither VM can regress on them:

  * With $ErrorActionPreference='Stop', ANYTHING a native command writes to
    stderr becomes a TERMINATING error. ssh emits "Warning: Permanently added ..."
    on first contact, so a successful call blew up the caller. Invoke-VmSsh pins
    the preference to Continue and adds LogLevel=ERROR.
  * Get-VMNetworkAdapter's IPAddresses comes from the Key-Value Pair integration
    service, whose daemon is absent from stock Ubuntu cloud images -- KVP reports
    "No Contact" and the list is empty, so a healthy guest looks dead. The lab NIC
    is pinned to a known address instead and nothing here needs guest tooling.
#>

Set-StrictMode -Version Latest

function Invoke-VmSsh {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Profile,
          [Parameter(Mandatory)][string] $Command,
          [int] $ConnectTimeout = 6)

    if (-not (Test-VmRunning -Profile $Profile)) {
        return [pscustomobject]@{ ExitCode = 255; Output = '' }
    }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & ssh -i $Profile.KeyPath -o StrictHostKeyChecking=no `
                     -o UserKnownHostsFile=/dev/null -o BatchMode=yes `
                     -o LogLevel=ERROR -o ConnectTimeout=$ConnectTimeout `
                     "$($Profile.GuestUser)@$($Profile.GuestIp)" $Command 2>&1
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output   = (($out | ForEach-Object { "$_" }) -join "`n").Trim()
        }
    } finally { $ErrorActionPreference = $prev }
}


function Test-VmRunning {
    param([Parameter(Mandatory)][hashtable] $Profile)
    $vm = Get-VM -Name $Profile.VmName -ErrorAction SilentlyContinue
    return ($null -ne $vm -and $vm.State -eq 'Running')
}


function Assert-VmExists {
    param([Parameter(Mandatory)][hashtable] $Profile)
    if (-not (Get-VM -Name $Profile.VmName -ErrorAction SilentlyContinue)) {
        throw "VM '$($Profile.VmName)' does not exist. Build it with the matching *Lab.ps1 :: Install-*Lab."
    }
}


function Test-VmSshReachable {
    param([Parameter(Mandatory)][hashtable] $Profile)
    return ((Invoke-VmSsh -Profile $Profile -Command 'true' -ConnectTimeout 5).ExitCode -eq 0)
}


function Start-Vm {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Profile,
          [int] $TimeoutSeconds = 300)

    Assert-VmExists -Profile $Profile
    if ((Get-VM -Name $Profile.VmName).State -ne 'Running') {
        Write-Host "[$($Profile.Tag)] starting $($Profile.VmName)"
        Start-VM -Name $Profile.VmName
    }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-VmSshReachable -Profile $Profile) {
            Write-Host "[$($Profile.Tag)] ssh reachable"
            return
        }
        Start-Sleep -Seconds 5
    }
    throw "Start-Vm: SSH did not answer within $TimeoutSeconds s"
}


function Restore-VmBaseline {
    <#
    .DESCRIPTION
    Scenarios run privileged containers that can and do wreck the guest. Rolling
    back a checkpoint takes seconds; rebuilding takes half an hour.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Profile)

    Assert-VmExists -Profile $Profile
    $snap = Get-VMSnapshot -VMName $Profile.VmName -Name 'baseline' -ErrorAction SilentlyContinue
    if (-not $snap) {
        throw "Restore-VmBaseline: no 'baseline' checkpoint on $($Profile.VmName)."
    }
    if ((Get-VM -Name $Profile.VmName).State -eq 'Running') {
        Stop-VM -Name $Profile.VmName -TurnOff -Force
    }
    Restore-VMSnapshot -VMSnapshot $snap -Confirm:$false
    Write-Host "[$($Profile.Tag)] restored to baseline"
}


function Set-VmPortProxy {
    <#
    .DESCRIPTION
    The lab switch is Internal: reachable from the host, not from a container.
    Docker Desktop resolves host.docker.internal to the host, so proxying here is
    what lets an in-container client reach the VM.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Profile)

    netsh interface portproxy delete v4tov4 listenport=$($Profile.SshPort) listenaddress=0.0.0.0 2>&1 | Out-Null
    netsh interface portproxy add v4tov4 `
        listenport=$($Profile.SshPort) listenaddress=0.0.0.0 `
        connectport=22 connectaddress=$($Profile.GuestIp) | Out-Null
    Write-Host "[$($Profile.Tag)] portproxy 0.0.0.0:$($Profile.SshPort) -> $($Profile.GuestIp):22"
}


function Test-VmKernelAbi {
    <#
    .DESCRIPTION
    Re-checked at run time, not just at build: unattended-upgrades has rolled a
    kernel forward despite the apt holds, and the failure is silent -- the LPE
    scenarios stop reproducing and verify.sh "passes" for the wrong reason.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Profile)

    $r = Invoke-VmSsh -Profile $Profile -Command 'uname -r'
    if ($r.ExitCode -ne 0) { throw "Test-VmKernelAbi: ssh failed: $($r.Output)" }
    $running = $r.Output
    $pattern = [regex]::Escape($Profile.KernelSeries) + '-(\d+)-generic'
    if ($running -notmatch $pattern) {
        throw "Test-VmKernelAbi: expected $($Profile.KernelSeries)-*, got '$running'"
    }
    $abi = [int]$Matches[1]
    if ($abi -ne $Profile.ExpectAbi) {
        throw "Test-VmKernelAbi: ABI $abi, expected $($Profile.ExpectAbi). Scenarios will NOT reproduce."
    }
    Write-Host "[$($Profile.Tag)] ABI $abi OK ($running)"
    return $running
}


function Wait-VmNetworkReady {
    <#
    .DESCRIPTION
    sshd answers well before DHCP and systemd-resolved settle after a checkpoint
    restore, so a harness that starts building immediately raced ahead of DNS and
    died on "lookup registry-1.docker.io ... server misbehaving". IPv4
    specifically: these hosts resolve IPv6 first and the NAT switch offers no
    IPv6 route out.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Profile,
          [int] $TimeoutSeconds = 180)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $r = Invoke-VmSsh -Profile $Profile -Command `
            'ip route show default | grep -q . && getent ahostsv4 registry-1.docker.io >/dev/null && echo READY'
        if ($r.ExitCode -eq 0 -and $r.Output -match 'READY') {
            Write-Host "[$($Profile.Tag)] network ready (default route + IPv4 DNS)"
            return
        }
        Start-Sleep -Seconds 5
    }
    throw "Wait-VmNetworkReady: no IPv4 DNS/default route after $TimeoutSeconds s"
}


function Copy-VmScenarios {
    <#
    .DESCRIPTION
    Replaces the Vagrant `synced_folder "..", "/meta4"`, which Hyper-V has no
    equivalent for. Deliberately a copy, not a live mount: these containers run
    --privileged and the Vagrant share let them write back into the host checkout.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Profile,
          [Parameter(Mandatory)][string] $Meta4Dir,
          [Parameter(Mandatory)][string[]] $Scenario)

    $target = "$($Profile.GuestUser)@$($Profile.GuestIp)"
    $sshArgs = @('-i', $Profile.KeyPath, '-o', 'StrictHostKeyChecking=no',
                 '-o', 'UserKnownHostsFile=/dev/null', '-o', 'BatchMode=yes',
                 '-o', 'LogLevel=ERROR')

    $r = Invoke-VmSsh -Profile $Profile -Command 'sudo mkdir -p /meta4 && sudo chown $(id -u):$(id -g) /meta4'
    if ($r.ExitCode -ne 0) { throw "Copy-VmScenarios: could not create /meta4: $($r.Output)" }

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        foreach ($s in $Scenario) {
            $src = Join-Path $Meta4Dir $s
            if (-not (Test-Path $src)) { throw "Copy-VmScenarios: no such scenario '$src'" }
            & scp @sshArgs -q -r $src "${target}:/meta4/" 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Copy-VmScenarios: scp of $s failed ($LASTEXITCODE)" }
            Write-Host "[$($Profile.Tag)] copied $s -> /meta4/$s"
        }
    } finally { $ErrorActionPreference = $prev }
}


function Invoke-VmScenarioTest {
    <#
    .DESCRIPTION
    verify.sh is BIND-MOUNTED in, not expected inside the image: none of these
    Dockerfiles COPY it, because the harness writes it into the sandbox at scoring
    time. Running it the way the README used to document exits 127.

    Pre-remediation a non-zero exit is CORRECT -- it is the proof the CVE
    reproduces on this kernel. Exit 42 means the scenario's precondition does not
    hold on this host at all.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Profile,
          [Parameter(Mandatory)][string] $Scenario)

    $tag = ($Scenario -replace '[^a-z0-9]', '')
    $remote = @"
cd /meta4 || exit 90
sudo docker build -q -t $tag $Scenario >/tmp/build-$tag.log 2>&1 || { echo BUILD_FAILED; tail -15 /tmp/build-$tag.log; echo "__EXIT__=91"; exit 0; }
test -f /meta4/$Scenario/verify.sh || { echo NO_VERIFY_SCRIPT; echo "__EXIT__=92"; exit 0; }
sudo docker run --rm --privileged -v /meta4/$Scenario/verify.sh:/verify.sh:ro $tag bash /verify.sh 2>&1 | tail -25
echo "__EXIT__=`${PIPESTATUS[0]}"
"@
    $r = Invoke-VmSsh -Profile $Profile -Command $remote -ConnectTimeout 15
    $code = -1
    if ($r.Output -match '__EXIT__=(\d+)') { $code = [int]$Matches[1] }
    [pscustomobject]@{
        Scenario = $Scenario
        ExitCode = $code
        Output   = (($r.Output -split "`n" | Where-Object { $_ -notmatch '__EXIT__=' }) -join "`n")
    }
}


function Get-VmSshConfig {
    <#
    .DESCRIPTION
    Replaces parsing `vagrant ssh-config`. run.py uses these to write a managed
    ~/.ssh/config block and create the docker context that DOCKER_CONTEXT points at.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Profile)

    [pscustomobject]@{
        HostName     = '127.0.0.1'
        Port         = $Profile.SshPort
        User         = $Profile.GuestUser
        IdentityFile = $Profile.KeyPath
        GuestIp      = $Profile.GuestIp
        VmName       = $Profile.VmName
    } | ConvertTo-Json -Compress
}


function Initialize-VmHost {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Profile,
          [switch] $NoRestore)

    Assert-VmExists -Profile $Profile
    if (-not $NoRestore) { Restore-VmBaseline -Profile $Profile }
    Start-Vm -Profile $Profile
    Set-VmPortProxy -Profile $Profile
    Test-VmKernelAbi -Profile $Profile | Out-Null
    Wait-VmNetworkReady -Profile $Profile
    Get-VmSshConfig -Profile $Profile
}

Export-ModuleMember -Function Invoke-VmSsh, Test-VmRunning, Assert-VmExists,
    Test-VmSshReachable, Start-Vm, Restore-VmBaseline, Set-VmPortProxy,
    Test-VmKernelAbi, Wait-VmNetworkReady, Copy-VmScenarios,
    Invoke-VmScenarioTest, Get-VmSshConfig, Initialize-VmHost
