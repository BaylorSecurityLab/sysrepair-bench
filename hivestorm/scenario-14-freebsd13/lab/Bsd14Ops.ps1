#Requires -RunAsAdministrator
<#
.SYNOPSIS
Runtime ops for hs14-bsd: the FreeBSD 13.2 target for hivestorm/scenario-14,
on Hyper-V instead of Vagrant/VirtualBox.

.DESCRIPTION
task.py finds lab/automatedlab.json and calls Initialize-Hs14Host, which restores
the baseline, starts the VM, publishes sshd on the host port the bridge container
expects, and confirms reachability. The SSH contract is deliberately identical to
what Vagrant provided, so solvers.py, scorer.py and the prompt need no changes.

WHY THIS ONE IS DIFFERENT FROM THE OTHER THREE. AutomatedLab has no FreeBSD
support, and the official FreeBSD VM image ships:
  * no cloud-init          (so no seed ISO can configure it)
  * no serial console      (COM1 captured 0 bytes -- loader.conf has no comconsole)
  * sshd disabled          (so no way in over the network)
There is therefore no unattended path at all. The VM was bootstrapped by injecting
keystrokes into the VIDEO console through Msvm_Keyboard, which needs two
non-obvious things:

  1. TypeText does nothing on this Hyper-V build. Only TypeKey (virtual key codes)
     is delivered. The tell was a screenshot showing the login banner repeating --
     Enter landed, characters did not.
  2. A PowerShell @{} hashtable is CASE-INSENSITIVE, so a char->VK map that adds
     'A' silently overwrites 'a' and every command types in capitals
     ("MKDIR: Command not found"). Use Dictionary[char,object].

Console state is readable via
Msvm_VirtualSystemManagementService.GetVirtualSystemThumbnailImage at 720x400
(the VM's text mode; other sizes return 32775). That screenshot loop is the only
reason this was debuggable -- reach for it first on any black-box guest.

ROOT SHELL IS tcsh. Every remote command must be wrapped in `sh -c '...'` or
bourne redirections fail with "Ambiguous output redirect".

Bootstrap left in place: sshd_enable=YES, nginx_enable=YES, the pipeline key in
/root/.ssh/authorized_keys, PermitRootLogin prohibit-password, a static lab
address on hn1, and console="comconsole,vidconsole" in /boot/loader.conf so the
next person is not blind.
#>

$ErrorActionPreference = 'Stop'

$script:VmName    = 'hs14-bsd'
$script:GuestUser = 'root'          # the account the injected key belongs to
$script:GuestIp   = '10.20.40.7'
$script:SshPort   = 2222            # bridge container expects host.docker.internal:2222
$script:KeyPath   = Join-Path $HOME '.ssh\srb_kernel'


function Invoke-Hs14Ssh {
    <#
    .SYNOPSIS
    Run a command in the guest under sh. Never throws; returns exit code + output.

    .DESCRIPTION
    Two traps folded in: PowerShell 5.1 turns native stderr into a TERMINATING
    error under EAP=Stop (so a poll loop dies on the first refused connection),
    and FreeBSD's root shell is tcsh, which rejects `2>&1`. Hence EAP=Continue
    plus an explicit `sh -c` wrapper.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Command,
          [int] $ConnectTimeout = 6)

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & ssh -i $script:KeyPath -o StrictHostKeyChecking=no `
                     -o UserKnownHostsFile=/dev/null -o BatchMode=yes `
                     -o LogLevel=ERROR -o ConnectTimeout=$ConnectTimeout `
                     "$($script:GuestUser)@$($script:GuestIp)" "sh -c '$Command'" 2>&1
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output   = (($out | ForEach-Object { "$_" }) -join "`n").Trim()
        }
    } finally { $ErrorActionPreference = $prev }
}


function Test-Hs14SshReachable {
    return ((Invoke-Hs14Ssh -Command 'true' -ConnectTimeout 5).ExitCode -eq 0)
}


function Start-Hs14 {
    [CmdletBinding()]
    param([int] $TimeoutSeconds = 300)

    if (-not (Get-VM -Name $script:VmName -ErrorAction SilentlyContinue)) {
        throw "VM '$($script:VmName)' does not exist. See lab/README-hyperv.md to build it."
    }
    if ((Get-VM -Name $script:VmName).State -ne 'Running') {
        Write-Host "[hs14] starting $($script:VmName)"
        Start-VM -Name $script:VmName
    }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Hs14SshReachable) { Write-Host '[hs14] ssh reachable'; return }
        Start-Sleep -Seconds 5
    }
    throw "Start-Hs14: sshd did not answer within $TimeoutSeconds s"
}


function Restore-Hs14Baseline {
    <#
    .SYNOPSIS
    Roll back to the post-seed checkpoint.

    .DESCRIPTION
    The baseline is taken AFTER seed.sh has planted the misconfigurations and
    after the seeder and roles.json have been erased, so a restore returns the
    box to exactly the state a graded run must start from. Rebuilding instead
    would mean redoing the whole keyboard-injection bootstrap.
    #>
    [CmdletBinding()]
    param()

    $snap = Get-VMSnapshot -VMName $script:VmName -Name 'baseline' -ErrorAction SilentlyContinue
    if (-not $snap) { throw "Restore-Hs14Baseline: no 'baseline' checkpoint on $($script:VmName)." }
    if ((Get-VM -Name $script:VmName).State -eq 'Running') {
        Stop-VM -Name $script:VmName -TurnOff -Force
    }
    Restore-VMSnapshot -VMSnapshot $snap -Confirm:$false

    # Default is Save, which parks the VM on host shutdown and can resume onto an
    # older disk state -- meta4-kernel silently reverted /meta4 that way, and it
    # was caught by hashing a deployed file rather than by anything failing. The
    # property is only settable while the VM is not running, and a restore is the
    # one point where that is guaranteed, so it self-heals here.
    if ((Get-VM -Name $script:VmName).AutomaticStopAction -ne 'ShutDown') {
        Set-VM -Name $script:VmName -AutomaticStopAction ShutDown
        Write-Host "[hs14] AutomaticStopAction -> ShutDown"
    }

    Write-Host "[hs14] restored to baseline"
}


function Set-Hs14PortProxy {
    <#
    .SYNOPSIS
    Publish the guest's sshd on 127.0.0.1:2222.

    .DESCRIPTION
    SRB-Kernel is an Internal switch: reachable from the host, not from a
    container. Docker Desktop resolves host.docker.internal to the host, so
    proxying here is what lets the bridge container reach the VM -- the same
    mechanism HS13 uses on 2223.
    #>
    [CmdletBinding()]
    param()

    netsh interface portproxy delete v4tov4 listenport=$script:SshPort listenaddress=0.0.0.0 2>&1 | Out-Null
    netsh interface portproxy add v4tov4 `
        listenport=$script:SshPort listenaddress=0.0.0.0 `
        connectport=22 connectaddress=$script:GuestIp | Out-Null
    Write-Host "[hs14] portproxy 0.0.0.0:$($script:SshPort) -> $($script:GuestIp):22"
}


function Test-Hs14Services {
    <#
    .SYNOPSIS
    Confirm the two services the verifier penalises for breaking are up.
    #>
    [CmdletBinding()]
    param()

    $r = Invoke-Hs14Ssh -Command 'service sshd status >/dev/null 2>&1 && echo sshd-ok; service nginx status >/dev/null 2>&1 && echo nginx-ok'
    Write-Host "[hs14] services: $($r.Output -replace "`n", ' ')"
    return $r.Output
}


function Install-Hs14SshAccess {
    <#
    .SYNOPSIS
    Authorise the bridge container's key on the VM.

    .DESCRIPTION
    task.py generates build/vagrant_key(.pub) per run and passes the public half
    here; the bridge Dockerfile then COPYs the private half in. So the harness
    owns the key the AGENT uses, and $script:KeyPath (the bootstrap key) is only
    how these ops functions reach the box. Both end up in root's authorized_keys.

    Idempotent: appends only if absent, so repeated runs do not grow the file.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $PublicKeyPath)

    if (-not (Test-Path $PublicKeyPath)) {
        throw "Install-Hs14SshAccess: public key not found: $PublicKeyPath"
    }
    $pub = (Get-Content $PublicKeyPath -Raw).Trim()
    # The key body is enough to test for presence and avoids quoting the comment.
    $body = ($pub -split '\s+')[1]

    Start-Hs14
    $r = Invoke-Hs14Ssh -Command (
        "mkdir -p /root/.ssh; chmod 700 /root/.ssh; " +
        "touch /root/.ssh/authorized_keys; " +
        "grep -q $body /root/.ssh/authorized_keys || echo `"$pub`" >> /root/.ssh/authorized_keys; " +
        "chmod 600 /root/.ssh/authorized_keys; wc -l < /root/.ssh/authorized_keys"
    )
    if ($r.ExitCode -ne 0) {
        throw "Install-Hs14SshAccess: failed to authorise key: $($r.Output)"
    }
    Write-Host "[hs14] bridge key authorised (authorized_keys lines: $($r.Output))"
}


function Initialize-Hs14Host {
    <#
    .SYNOPSIS
    One call for task.py: restore -> start -> portproxy -> emit the SSH contract.
    #>
    [CmdletBinding()]
    param([switch] $NoRestore)

    if (-not $NoRestore) { Restore-Hs14Baseline }
    Start-Hs14
    Set-Hs14PortProxy
    Test-Hs14Services | Out-Null
    [pscustomobject]@{
        HostName     = '127.0.0.1'
        Port         = $script:SshPort
        User         = $script:GuestUser
        IdentityFile = $script:KeyPath
        GuestIp      = $script:GuestIp
        VmName       = $script:VmName
    } | ConvertTo-Json -Compress
}
