#Requires -RunAsAdministrator
<#
.SYNOPSIS
Runtime ops for meta4-kernel: start, restore to baseline, expose SSH, report
readiness. The Hyper-V replacement for `vagrant up` / `vagrant ssh-config`.

.DESCRIPTION
run.py's `vagrant_vm:` preset key brought a VM up and pointed DOCKER_CONTEXT at
it over SSH. This provides the same contract without Vagrant:

    Start-KernelVm          ~ vagrant up
    Restore-KernelBaseline  ~ vagrant destroy && vagrant up, but in seconds
    Get-KernelSshConfig     ~ vagrant ssh-config  (emits JSON for run.py)

meta4 scenarios S21/S22 run as containers INSIDE this VM so they share its
pinned 5.15.0-25 kernel; the host talks to its Docker daemon over SSH.

Build it first with KernelLab.ps1 :: Install-KernelLab.
#>

$ErrorActionPreference = 'Stop'

$script:VmName    = 'meta4-kernel'
$script:GuestUser = 'vagrant'
$script:GuestIp   = '10.20.40.5'
$script:SshPort   = 2224          # host-side; HS13 owns 2223
$script:KeyPath   = Join-Path $HOME '.ssh\srb_kernel'
$script:ExpectAbi = 25


function Test-KernelVmExists {
    [bool](Get-VM -Name $script:VmName -ErrorAction SilentlyContinue)
}


function Assert-KernelVmExists {
    if (-not (Test-KernelVmExists)) {
        throw @"
VM '$($script:VmName)' does not exist. Build it first:
    . .\KernelLab.ps1
    Install-KernelLab
"@
    }
}


function Start-KernelVm {
    <#
    .SYNOPSIS
    Start the VM if not already running and wait for SSH to answer.
    #>
    [CmdletBinding()]
    param([int] $TimeoutSeconds = 300)

    Assert-KernelVmExists
    $vm = Get-VM -Name $script:VmName
    if ($vm.State -ne 'Running') {
        Write-Host "[kernel] starting $($script:VmName)"
        Start-VM -Name $script:VmName
    } else {
        Write-Host "[kernel] $($script:VmName) already running"
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-KernelSshReachable) {
            Write-Host '[kernel] ssh reachable'
            return
        }
        Start-Sleep -Seconds 5
    }
    throw "Start-KernelVm: SSH did not come up within $TimeoutSeconds s"
}


function Restore-KernelBaseline {
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

    Assert-KernelVmExists
    $snap = Get-VMSnapshot -VMName $script:VmName -Name 'baseline' -ErrorAction SilentlyContinue
    if (-not $snap) {
        throw "Restore-KernelBaseline: no 'baseline' checkpoint on $($script:VmName). Re-run Install-KernelLab."
    }
    if ((Get-VM -Name $script:VmName).State -eq 'Running') {
        Stop-VM -Name $script:VmName -TurnOff -Force
    }
    Restore-VMSnapshot -VMSnapshot $snap -Confirm:$false
    Write-Host "[kernel] $($script:VmName) restored to baseline"
}


function Get-KernelIpAddress {
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
    if (-not (Test-KernelVmExists)) { return $null }
    if ((Get-VM -Name $script:VmName).State -ne 'Running') { return $null }
    return $script:GuestIp
}


function Set-KernelPortProxy {
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

    $ip = Get-KernelIpAddress
    if (-not $ip) { throw 'Set-KernelPortProxy: VM has no IPv4 address yet. Is it running?' }

    netsh interface portproxy delete v4tov4 listenport=$script:SshPort listenaddress=0.0.0.0 2>&1 | Out-Null
    netsh interface portproxy add v4tov4 `
        listenport=$script:SshPort listenaddress=0.0.0.0 `
        connectport=22 connectaddress=$ip | Out-Null
    Write-Host "[kernel] portproxy 0.0.0.0:$($script:SshPort) -> ${ip}:22"
}


function Test-KernelSshReachable {
    <#
    .SYNOPSIS
    True when sshd answers as the provisioned user. BatchMode so a missing key
    fails immediately instead of hanging on a password prompt.
    #>
    [CmdletBinding()]
    param()

    $ip = Get-KernelIpAddress
    if (-not $ip) { return $false }
    ssh -i $script:KeyPath -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null `
        -o ConnectTimeout=5 -o BatchMode=yes "$($script:GuestUser)@$ip" 'true' 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}


function Test-KernelAbi {
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

    $ip = Get-KernelIpAddress
    if (-not $ip) { throw 'Test-KernelAbi: VM has no IPv4 address.' }
    $running = (ssh -i $script:KeyPath -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null `
                    -o BatchMode=yes "$($script:GuestUser)@$ip" 'uname -r' 2>$null).Trim()
    if ($running -notmatch '^5\.15\.0-(\d+)-generic') {
        throw "Test-KernelAbi: unexpected kernel '$running'"
    }
    $abi = [int]$Matches[1]
    if ($abi -ne $script:ExpectAbi) {
        throw "Test-KernelAbi: ABI $abi, expected $($script:ExpectAbi). Scenarios S21/S22 will NOT reproduce."
    }
    Write-Host "[kernel] ABI $abi OK ($running)"
    return $running
}


function Get-KernelSshConfig {
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
        GuestIp      = (Get-KernelIpAddress)
        VmName       = $script:VmName
    } | ConvertTo-Json -Compress
}


function Copy-KernelScenarios {
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
    param([string[]] $Scenario = @('scenario-19','scenario-21','scenario-22','scenario-117'))

    $ip = Get-KernelIpAddress
    if (-not $ip) { throw 'Copy-KernelScenarios: VM has no IPv4 address.' }
    $meta4 = Split-Path -Parent (Split-Path -Parent $PSCommandPath)   # ...\meta4
    $target = "$($script:GuestUser)@$ip"
    $sshArgs = @('-i', $script:KeyPath, '-o', 'StrictHostKeyChecking=no',
                 '-o', 'UserKnownHostsFile=/dev/null', '-o', 'BatchMode=yes')

    ssh @sshArgs $target 'sudo mkdir -p /meta4 && sudo chown $(id -u):$(id -g) /meta4' | Out-Null
    foreach ($s in $Scenario) {
        $src = Join-Path $meta4 $s
        if (-not (Test-Path $src)) { throw "Copy-KernelScenarios: no such scenario '$src'" }
        scp @sshArgs -r $src "${target}:/meta4/" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Copy-KernelScenarios: scp of $s failed ($LASTEXITCODE)" }
        Write-Host "[kernel] copied $s -> /meta4/$s"
    }
}


function Invoke-KernelScenarioTest {
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

    $ip = Get-KernelIpAddress
    if (-not $ip) { throw 'Invoke-KernelScenarioTest: VM has no IPv4 address.' }
    $tag = ($Scenario -replace '[^a-z0-9]', '')
    $remote = @"
set -e
cd /meta4
sudo docker build -q -t $tag $Scenario >/dev/null
set +e
sudo docker run --rm --privileged $tag bash /verify.sh 2>&1 | tail -20
echo "__EXIT__=`${PIPESTATUS[0]}"
"@
    $out = ssh -i $script:KeyPath -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null `
               -o BatchMode=yes "$($script:GuestUser)@$ip" $remote 2>&1
    $code = -1
    if ($out -match '__EXIT__=(\d+)') { $code = [int]$Matches[1] }
    [pscustomobject]@{
        Scenario = $Scenario
        ExitCode = $code
        Output   = (($out | Where-Object { $_ -notmatch '__EXIT__=' }) -join "`n")
    }
}


function Initialize-KernelHost {
    <#
    .SYNOPSIS
    One call for run.py: restore -> start -> portproxy -> verify ABI -> emit config.
    #>
    [CmdletBinding()]
    param([switch] $NoRestore)

    Assert-KernelVmExists
    if (-not $NoRestore) { Restore-KernelBaseline }
    Start-KernelVm
    Set-KernelPortProxy
    Test-KernelAbi | Out-Null
    Get-KernelSshConfig
}
