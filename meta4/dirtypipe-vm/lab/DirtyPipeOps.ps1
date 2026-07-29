#Requires -RunAsAdministrator
<#
.SYNOPSIS
Runtime ops for meta4-dirtypipe: start, restore to baseline, expose SSH, report
readiness. The Hyper-V replacement for `vagrant up` / `vagrant ssh-config`.

.DESCRIPTION
run.py's `vagrant_vm:` preset key brought a VM up and pointed DOCKER_CONTEXT at
it over SSH. This provides the same contract without Vagrant:

    Start-DirtyPipeVm          ~ vagrant up
    Restore-DirtyPipeBaseline  ~ vagrant destroy && vagrant up, but in seconds
    Get-DirtyPipeSshConfig     ~ vagrant ssh-config  (emits JSON for run.py)

meta4 scenarios S21/S22 run as containers INSIDE this VM so they share its
pinned 5.13.0-27 kernel; the host talks to its Docker daemon over SSH.

Build it first with DirtyPipeLab.ps1 :: Install-DirtyPipeLab.
#>

$ErrorActionPreference = 'Stop'

$script:VmName    = 'meta4-dirtypipe'
$script:GuestUser = 'vagrant'
$script:GuestIp   = '10.20.40.6'
$script:SshPort   = 2225          # host-side; HS13 owns 2223
$script:KeyPath   = Join-Path $HOME '.ssh\srb_dirtypipe'
$script:ExpectAbi = 27


function Invoke-DirtyPipeSsh {
    <#
    .SYNOPSIS
    Run a command in the guest. Never throws; returns exit code + output.

    .DESCRIPTION
    PowerShell 5.1 trap: with $ErrorActionPreference='Stop', ANYTHING a native
    command writes to stderr becomes a TERMINATING error. ssh writes
    "Warning: Permanently added ... to the list of known hosts" to stderr on
    first contact, so a perfectly successful call blows up the caller. Pinning
    the preference to Continue for the duration is the fix; LogLevel=ERROR
    silences the specific warning as well.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Command,
          [int] $ConnectTimeout = 6)

    $ip = Get-DirtyPipeIpAddress
    if (-not $ip) { return [pscustomobject]@{ ExitCode = 255; Output = '' } }

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & ssh -i $script:KeyPath -o StrictHostKeyChecking=no `
                     -o UserKnownHostsFile=/dev/null -o BatchMode=yes `
                     -o LogLevel=ERROR -o ConnectTimeout=$ConnectTimeout `
                     "$($script:GuestUser)@$ip" $Command 2>&1
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output   = (($out | ForEach-Object { "$_" }) -join "`n").Trim()
        }
    } finally {
        $ErrorActionPreference = $prev
    }
}


function Test-DirtyPipeVmExists {
    [bool](Get-VM -Name $script:VmName -ErrorAction SilentlyContinue)
}


function Assert-DirtyPipeVmExists {
    if (-not (Test-DirtyPipeVmExists)) {
        throw @"
VM '$($script:VmName)' does not exist. Build it first:
    . .\DirtyPipeLab.ps1
    Install-DirtyPipeLab
"@
    }
}


function Start-DirtyPipeVm {
    <#
    .SYNOPSIS
    Start the VM if not already running and wait for SSH to answer.
    #>
    [CmdletBinding()]
    param([int] $TimeoutSeconds = 300)

    Assert-DirtyPipeVmExists
    $vm = Get-VM -Name $script:VmName
    if ($vm.State -ne 'Running') {
        Write-Host "[dirtypipe] starting $($script:VmName)"
        Start-VM -Name $script:VmName
    } else {
        Write-Host "[dirtypipe] $($script:VmName) already running"
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-DirtyPipeSshReachable) {
            Write-Host '[dirtypipe] ssh reachable'
            return
        }
        Start-Sleep -Seconds 5
    }
    throw "Start-DirtyPipeVm: SSH did not come up within $TimeoutSeconds s"
}


function Restore-DirtyPipeBaseline {
    <#
    .SYNOPSIS
    Roll back to the post-provision checkpoint.

    .DESCRIPTION
    The point of the baseline: scenarios run privileged containers that can and
    do wreck the guest. Rolling back a checkpoint takes seconds; rebuilding the
    VM takes half an hour, which is why the Vagrant flow was painful.
    #>
    [CmdletBinding()]
    param()

    Assert-DirtyPipeVmExists
    $snap = Get-VMSnapshot -VMName $script:VmName -Name 'baseline' -ErrorAction SilentlyContinue
    if (-not $snap) {
        throw "Restore-DirtyPipeBaseline: no 'baseline' checkpoint on $($script:VmName). Re-run Install-DirtyPipeLab."
    }
    if ((Get-VM -Name $script:VmName).State -eq 'Running') {
        Stop-VM -Name $script:VmName -TurnOff -Force
    }
    Restore-VMSnapshot -VMSnapshot $snap -Confirm:$false
    Write-Host "[dirtypipe] $($script:VmName) restored to baseline"
}


function Get-DirtyPipeIpAddress {
    <#
    .SYNOPSIS
    The guest's lab address. Fixed, not discovered.

    .DESCRIPTION
    Discovery via Get-VMNetworkAdapter's IPAddresses depends on the Key-Value
    Pair integration service, whose daemon (linux-cloud-tools-virtual) is absent
    from stock Ubuntu cloud images -- KVP reports "No Contact" and the list comes
    back empty, which is exactly how the first build appeared to hang. The lab
    NIC is pinned to a known address, so this needs nothing from the guest.
    #>
    if (-not (Test-DirtyPipeVmExists)) { return $null }
    if ((Get-VM -Name $script:VmName).State -ne 'Running') { return $null }
    return $script:GuestIp
}


function Set-DirtyPipePortProxy {
    <#
    .SYNOPSIS
    Publish the guest's sshd on 127.0.0.1:<SshPort>.

    .DESCRIPTION
    SRB-Kernel is an Internal switch, so the guest is reachable from the host but
    not from a container. Docker Desktop's `host.docker.internal` resolves to the
    host, so proxying here is what lets an in-container client reach the VM --
    the same trick HS13 uses on 2223.
    #>
    [CmdletBinding()]
    param()

    $ip = Get-DirtyPipeIpAddress
    if (-not $ip) { throw 'Set-DirtyPipePortProxy: VM has no IPv4 address yet. Is it running?' }

    netsh interface portproxy delete v4tov4 listenport=$script:SshPort listenaddress=0.0.0.0 2>&1 | Out-Null
    netsh interface portproxy add v4tov4 `
        listenport=$script:SshPort listenaddress=0.0.0.0 `
        connectport=22 connectaddress=$ip | Out-Null
    Write-Host "[dirtypipe] portproxy 0.0.0.0:$($script:SshPort) -> ${ip}:22"
}


function Test-DirtyPipeSshReachable {
    <#
    .SYNOPSIS
    True when sshd answers as the provisioned user. BatchMode so a missing key
    fails immediately instead of hanging on a password prompt.
    #>
    [CmdletBinding()]
    param()

    return ((Invoke-DirtyPipeSsh -Command 'true' -ConnectTimeout 5).ExitCode -eq 0)
}


function Test-DirtyPipeAbi {
    <#
    .SYNOPSIS
    Confirm the guest is still on the pinned ABI.

    .DESCRIPTION
    Worth re-checking at run time, not just at build: unattended-upgrades has
    been known to roll a kernel forward despite the apt holds, and the failure is
    silent -- the LPE scenarios simply stop reproducing and verify.sh "passes".
    #>
    [CmdletBinding()]
    param()

    $r = Invoke-DirtyPipeSsh -Command 'uname -r'
    if ($r.ExitCode -ne 0) { throw "Test-DirtyPipeAbi: ssh failed: $($r.Output)" }
    $running = $r.Output
    if ($running -notmatch '5\.13\.0-(\d+)-generic') {
        throw "Test-DirtyPipeAbi: unexpected kernel '$running'"
    }
    $abi = [int]$Matches[1]
    if ($abi -ne $script:ExpectAbi) {
        throw "Test-DirtyPipeAbi: ABI $abi, expected $($script:ExpectAbi). Scenarios S21/S22 will NOT reproduce."
    }
    Write-Host "[dirtypipe] ABI $abi OK ($running)"
    return $running
}


function Wait-DirtyPipeNetworkReady {
    <#
    .SYNOPSIS
    Block until the guest has a default route AND working IPv4 DNS.

    .DESCRIPTION
    sshd answers well before DHCP and systemd-resolved have settled after a
    checkpoint restore. Start-DirtyPipeVm only waits for SSH, so the harness raced
    ahead and its first `docker build` died with

        lookup registry-1.docker.io on 127.0.0.53:53: server misbehaving

    even though the same lookup succeeded seconds later. IPv4 specifically:
    registry-1.docker.io resolves to IPv6 first and the NAT switch gives no IPv6
    route out, so an A record is what actually has to be reachable.
    #>
    [CmdletBinding()]
    param([int] $TimeoutSeconds = 240)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $r = Invoke-DirtyPipeSsh -Command @'
ip route show default | grep -q . || exit 1
getent ahostsv4 registry-1.docker.io >/dev/null 2>&1 || exit 2
echo READY
'@
        if ($r.ExitCode -eq 0 -and $r.Output -match 'READY') {
            Write-Host '[dirtypipe] network ready (default route + IPv4 DNS)'
            return
        }
        Start-Sleep -Seconds 5
    }
    throw @"
Wait-DirtyPipeNetworkReady: no default route / IPv4 DNS after $TimeoutSeconds s.
The NAT NIC must be CONNECTED for scenario image builds -- they pull from Docker
Hub. Check: Get-VMNetworkAdapter -VMName $($script:VmName)
"@
}


function Get-DirtyPipeSshConfig {
    <#
    .SYNOPSIS
    Emit the SSH contract as JSON for run.py to consume.

    .DESCRIPTION
    Replaces parsing `vagrant ssh-config`. run.py uses these to write a managed
    ~/.ssh/config block and create the `docker context` that points DOCKER_CONTEXT
    at this VM.
    #>
    [CmdletBinding()]
    param()

    [pscustomobject]@{
        HostName     = '127.0.0.1'
        Port         = $script:SshPort
        User         = $script:GuestUser
        IdentityFile = $script:KeyPath
        GuestIp      = (Get-DirtyPipeIpAddress)
        VmName       = $script:VmName
    } | ConvertTo-Json -Compress
}


function Copy-DirtyPipeScenarios {
    <#
    .SYNOPSIS
    Replacement for the Vagrant `synced_folder "..", "/meta4"`.

    .DESCRIPTION
    Hyper-V has no synced-folder equivalent, so the scenario trees are copied in
    over SSH instead. Deliberately a COPY, not a live mount: the Vagrant share
    let a privileged scenario container write back into the host checkout, and
    these scenarios run --privileged specifically to exercise kernel LPEs.

    Only the directories asked for are copied, so a full-suite sync does not drag
    ~300 scenarios onto the guest.
    #>
    [CmdletBinding()]
    param([string[]] $Scenario = @('scenario-19'))

    $ip = Get-DirtyPipeIpAddress
    if (-not $ip) { throw 'Copy-DirtyPipeScenarios: VM has no IPv4 address.' }
    # $PSCommandPath is .../meta4/dirtypipe-vm/lab/DirtyPipeOps.ps1, so meta4 is three
    # parents up: lab -> dirtypipe-vm -> meta4.
    $meta4 = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    if (-not (Test-Path (Join-Path $meta4 'dirtypipe-vm'))) {
        throw "Copy-DirtyPipeScenarios: resolved meta4 dir looks wrong: $meta4"
    }
    $target = "$($script:GuestUser)@$ip"
    $sshArgs = @('-i', $script:KeyPath, '-o', 'StrictHostKeyChecking=no',
                 '-o', 'UserKnownHostsFile=/dev/null', '-o', 'BatchMode=yes',
                 '-o', 'LogLevel=ERROR')

    $r = Invoke-DirtyPipeSsh -Command 'sudo mkdir -p /meta4 && sudo chown $(id -u):$(id -g) /meta4'
    if ($r.ExitCode -ne 0) { throw "Copy-DirtyPipeScenarios: could not create /meta4: $($r.Output)" }

    # scp is a native command too: its progress/warning output on stderr becomes
    # a terminating error under EAP=Stop. Same fix as Invoke-DirtyPipeSsh.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        foreach ($s in $Scenario) {
            $src = Join-Path $meta4 $s
            if (-not (Test-Path $src)) { throw "Copy-DirtyPipeScenarios: no such scenario '$src'" }
            & scp @sshArgs -q -r $src "${target}:/meta4/" 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Copy-DirtyPipeScenarios: scp of $s failed ($LASTEXITCODE)" }
            Write-Host "[dirtypipe] copied $s -> /meta4/$s"
        }
    } finally {
        $ErrorActionPreference = $prev
    }
}


function Invoke-DirtyPipeScenarioTest {
    <#
    .SYNOPSIS
    Build and run one scenario's verify.sh inside the VM, returning its exit code.

    .DESCRIPTION
    Pre-remediation, verify.sh is EXPECTED TO FAIL (non-zero) on a vulnerable
    host -- that failure is the proof the CVE actually reproduces on this
    kernel. A pass before remediation means the scenario is not exercising
    anything, which is the silent-failure mode the pinned ABI exists to prevent.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Scenario)

    $tag = ($Scenario -replace '[^a-z0-9]', '')
    # verify.sh is BIND-MOUNTED in, not expected inside the image. None of these
    # Dockerfiles COPY it: the inspect harness writes it into the sandbox at
    # scoring time (scorer.py::_run_verify), so the image never carries its own
    # grader. meta4/dirtypipe-vm/README.md documents `docker run ... bash /verify.sh`,
    # which cannot work -- it exits 127 with "No such file or directory".
    # Mounting read-only mirrors what the scorer effectively does.
    #
    # PIPESTATUS is backtick-escaped so PowerShell leaves the $ for bash.
    $remote = @"
cd /meta4 || exit 90
sudo docker build -q -t $tag $Scenario >/tmp/build-$tag.log 2>&1 || { echo BUILD_FAILED; tail -15 /tmp/build-$tag.log; echo "__EXIT__=91"; exit 0; }
test -f /meta4/$Scenario/verify.sh || { echo "NO_VERIFY_SCRIPT"; echo "__EXIT__=92"; exit 0; }
sudo docker run --rm --privileged \
     -v /meta4/$Scenario/verify.sh:/verify.sh:ro \
     $tag bash /verify.sh 2>&1 | tail -25
echo "__EXIT__=`${PIPESTATUS[0]}"
"@
    $r = Invoke-DirtyPipeSsh -Command $remote -ConnectTimeout 15
    $code = -1
    if ($r.Output -match '__EXIT__=(\d+)') { $code = [int]$Matches[1] }
    [pscustomobject]@{
        Scenario = $Scenario
        ExitCode = $code
        Output   = (($r.Output -split "`n" | Where-Object { $_ -notmatch '__EXIT__=' }) -join "`n")
    }
}


function Initialize-DirtyPipeHost {
    <#
    .SYNOPSIS
    One call for run.py: restore -> start -> portproxy -> verify ABI -> emit config.
    #>
    [CmdletBinding()]
    param([switch] $NoRestore)

    Assert-DirtyPipeVmExists
    if (-not $NoRestore) { Restore-DirtyPipeBaseline }
    Start-DirtyPipeVm
    Set-DirtyPipePortProxy
    Test-DirtyPipeAbi | Out-Null
    # Must come before the harness starts building: sshd is up long before DNS.
    Wait-DirtyPipeNetworkReady
    Get-DirtyPipeSshConfig
}
