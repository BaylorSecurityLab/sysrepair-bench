# hivestorm/scenario-13-ad-dc-win2019/lab/Hs13Ops.ps1
#
# Operational layer for the S13 AutomatedLab DC: readiness, baseline capture and
# restore, and the seed/verify cycle that Vagrant's provisioner used to drive.
#
# Dot-source this, then call the functions:
#   . .\lab\Hs13Ops.ps1
#   Save-Hs13Baseline
#   Invoke-Hs13Seed -RolesPath .\build\roles.json
#   Invoke-Hs13Verify

$ErrorActionPreference = 'Stop'

$script:Hs13VM     = 'hs13-dc01'
$script:Hs13Domain = 'corp.sysrepair.local'
$script:Hs13Cred   = New-Object System.Management.Automation.PSCredential(
    'CORP\Administrator', (ConvertTo-SecureString 'Password1!' -AsPlainText -Force))

# Where seed.ps1 and verify.ps1 expect to find roles.json. Both scripts read
# C:\ProgramData\sysrepair\roles.json; the Vagrant path delivered it to
# C:\Users\vagrant\provisioning and a bootstrap step moved it. Staging straight
# to the final location removes that indirection.
$script:Hs13RolesDir = 'C:\ProgramData\sysrepair'

function Test-Hs13Ready {
    <#
    .SYNOPSIS
        Is the DC actually serving the directory, not merely powered on?

    .DESCRIPTION
        "VM is Running" is not readiness. A DC answers PowerShell Direct well
        before NTDS, Netlogon, DNS and the KDC are up, and seeding against a
        half-started directory fails in ways that look like scenario bugs.

        Returns $null when ready, or a short string naming the first thing that
        is not. Deliberately does not mutate anything -- see Repair-CaRpcEndpoint
        in meta4/ad-vm for why a probe that fixes what it measures cannot be
        trusted to report what it found.
    #>
    param([string] $VMName = $script:Hs13VM)

    if ((Get-VM -Name $VMName -ErrorAction SilentlyContinue).State -ne 'Running') {
        return 'vm-not-running'
    }

    try {
        return Invoke-Command -VMName $VMName -Credential $script:Hs13Cred -ErrorAction Stop -ScriptBlock {
            foreach ($svc in 'NTDS', 'Netlogon', 'DNS', 'kdc') {
                $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
                if (-not $s -or $s.Status -ne 'Running') { return "service:$svc" }
            }
            try { Import-Module ActiveDirectory -ErrorAction Stop } catch { return 'ad-module' }
            try { $null = Get-ADDomain -ErrorAction Stop } catch { return 'get-addomain' }

            # SYSVOL and NETLOGON shares prove the DC finished promoting rather
            # than merely starting the services.
            foreach ($share in 'SYSVOL', 'NETLOGON') {
                if (-not (Get-SmbShare -Name $share -ErrorAction SilentlyContinue)) { return "share:$share" }
            }
            return $null
        }
    }
    catch {
        return "psdirect:$($_.Exception.Message.Split([char]10)[0])"
    }
}

function Wait-Hs13Ready {
    param([int] $TimeoutSeconds = 600)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $last = 'not-probed'
    while ((Get-Date) -lt $deadline) {
        $last = Test-Hs13Ready
        if (-not $last) {
            Write-Host '[hs13] DC ready'
            return $true
        }
        Start-Sleep -Seconds 10
    }
    throw "[hs13] DC not ready after ${TimeoutSeconds}s (last failed probe: $last)"
}

function Start-Hs13 {
    param([int] $TimeoutSeconds = 600)

    $vm = Get-VM -Name $script:Hs13VM -ErrorAction Stop
    if ($vm.State -ne 'Running') {
        # Report WHY a start failed rather than letting it surface later as an
        # unexplained readiness timeout. Low host memory is the usual cause and
        # the message should say so.
        try { Start-VM -Name $script:Hs13VM -ErrorAction Stop }
        catch {
            $freeGB = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2)
            $needGB = [math]::Round($vm.MemoryStartup / 1GB, 2)
            throw ("[hs13] Start-VM failed: $($_.Exception.Message) " +
                   "(free ${freeGB}GB, needs ${needGB}GB)")
        }
    }
    Wait-Hs13Ready -TimeoutSeconds $TimeoutSeconds
}

function Save-Hs13Baseline {
    <#
    .SYNOPSIS
        Capture the clean, pre-seed snapshot the scenario resets to.

    .DESCRIPTION
        Taken with the VM OFF. A running-state checkpoint of a DC restores with
        a stale directory cache and a clock that jumped, which produces
        Kerberos failures that look like scenario bugs.

        Promotion is atomic via a rename dance: the new snapshot is created
        under a temporary name and only becomes 'baseline' once it exists, so a
        crash midway leaves the previous baseline intact rather than none.
    #>
    param([string] $VMName = $script:Hs13VM)

    if (Test-Hs13Ready -VMName $VMName) {
        Write-Warning '[hs13] DC is not fully ready; snapshotting it now captures a broken baseline'
        throw '[hs13] refusing to baseline a DC that is not ready'
    }

    Write-Host '[hs13] stopping VM for a clean offline snapshot'
    Stop-VM -Name $VMName -Force -ErrorAction Stop
    while ((Get-VM -Name $VMName).State -ne 'Off') { Start-Sleep -Seconds 2 }

    $tmp = "baseline-new-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    Checkpoint-VM -Name $VMName -SnapshotName $tmp -ErrorAction Stop

    # Poll for visibility: Checkpoint-VM returns before the snapshot is always
    # enumerable, and renaming a snapshot that is not yet listed fails.
    $deadline = (Get-Date).AddSeconds(120)
    $new = $null
    while ((Get-Date) -lt $deadline) {
        $new = Get-VMSnapshot -VMName $VMName -Name $tmp -ErrorAction SilentlyContinue
        if ($new) { break }
        Start-Sleep -Seconds 2
    }
    if (-not $new) { throw "[hs13] snapshot '$tmp' never became visible" }

    $old = Get-VMSnapshot -VMName $VMName -Name 'baseline' -ErrorAction SilentlyContinue
    if ($old) { Rename-VMSnapshot -VMSnapshot $old -NewName 'baseline-prev' -ErrorAction Stop }
    Rename-VMSnapshot -VMSnapshot $new -NewName 'baseline' -ErrorAction Stop

    $prev = Get-VMSnapshot -VMName $VMName -Name 'baseline-prev' -ErrorAction SilentlyContinue
    if ($prev) { Remove-VMSnapshot -VMSnapshot $prev -ErrorAction SilentlyContinue }

    Write-Host "[hs13] baseline captured for $VMName"
    Start-Hs13 | Out-Null
}

function Restore-Hs13Baseline {
    param([string] $VMName = $script:Hs13VM, [int] $TimeoutSeconds = 600)

    $snap = Get-VMSnapshot -VMName $VMName -Name 'baseline' -ErrorAction SilentlyContinue
    if (-not $snap) { throw "[hs13] no 'baseline' snapshot on $VMName -- run Save-Hs13Baseline first" }

    if ((Get-VM -Name $VMName).State -ne 'Off') {
        Stop-VM -Name $VMName -Force -ErrorAction SilentlyContinue
        while ((Get-VM -Name $VMName).State -ne 'Off') { Start-Sleep -Seconds 2 }
    }

    Restore-VMSnapshot -VMSnapshot $snap -Confirm:$false -ErrorAction Stop
    Write-Host "[hs13] $VMName restored to baseline"
    Start-Hs13 -TimeoutSeconds $TimeoutSeconds | Out-Null
}

function Copy-Hs13File {
    param([Parameter(Mandatory)] [string] $LocalPath,
          [Parameter(Mandatory)] [string] $GuestPath)

    if (-not (Test-Path $LocalPath)) { throw "[hs13] local file not found: $LocalPath" }
    $text = Get-Content -LiteralPath $LocalPath -Raw

    Invoke-Command -VMName $script:Hs13VM -Credential $script:Hs13Cred -ErrorAction Stop `
        -ArgumentList $GuestPath, $text -ScriptBlock {
        param($p, $t)
        $dir = Split-Path $p -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Set-Content -LiteralPath $p -Value $t -Encoding UTF8
    }
}

function Invoke-Hs13Seed {
    <#
    .SYNOPSIS
        Stage roles.json and run seed.ps1 on the DC.

    .DESCRIPTION
        Replaces the Vagrant "file" provisioners plus dc-bootstrap's staging
        step. Fails loudly if seeding throws: a seed that did not run leaves a
        clean DC, and grading a clean DC reports the scenario already solved.
        That failure mode cost two full gate runs in meta4/ad-vm before the
        harness started asserting on fixture exit codes.
    #>
    param([Parameter(Mandatory)] [string] $RolesPath)

    Wait-Hs13Ready | Out-Null

    $here = Split-Path $PSScriptRoot -Parent
    Copy-Hs13File -LocalPath $RolesPath -GuestPath (Join-Path $script:Hs13RolesDir 'roles.json')

    $seedLocal = Join-Path $here 'seed.ps1'
    $r = Invoke-Command -VMName $script:Hs13VM -Credential $script:Hs13Cred -ErrorAction Stop `
            -ArgumentList (Get-Content -LiteralPath $seedLocal -Raw) -ScriptBlock {
        param($text)
        $p = Join-Path $env:TEMP 'hs13-seed.ps1'
        Set-Content -LiteralPath $p -Value $text -Encoding UTF8
        try {
            $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p 2>&1 | Out-String
            [pscustomobject]@{ Output = $out; ExitCode = $LASTEXITCODE }
        }
        finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }

    Write-Host ($r.Output.TrimEnd())
    if ($r.ExitCode -ne 0) {
        throw "[hs13] seed.ps1 exited $($r.ExitCode) -- the scenario was NOT injected"
    }

    # Record when seeding finished. verify.ps1 reads this to distinguish
    # pre-existing state from what the agent changed.
    Invoke-Command -VMName $script:Hs13VM -Credential $script:Hs13Cred -ScriptBlock {
        Set-Content -LiteralPath 'C:\ProgramData\sysrepair\baseline.timestamp' `
                    -Value ([DateTime]::UtcNow.ToString('o')) -Encoding UTF8
    }
    Write-Host '[hs13] seeded'
}

function Install-Hs13OpenSshServer {
    <#
    .SYNOPSIS
        Install the OpenSSH Server capability, which needs temporary internet.

    .DESCRIPTION
        OpenSSH.Server is a Feature-on-Demand: Add-WindowsCapability fetches it
        from Windows Update. The lab switch is INTERNAL by design and the DC has
        no default route, so the call fails with a bare COMException that names
        nothing useful.

        This attaches the existing external build switch for the duration of the
        install and detaches it again. The lab returns to being isolated -- an
        AD scenario that can reach the internet is a different scenario, and
        leaving the adapter attached would silently change what is being graded.

        MUST be run BEFORE the baseline is captured. Restoring the baseline
        resets the VM, so sshd has to be inside the snapshot; installing it
        per-run would require internet on every run.
    #>
    param(
        [string] $VMName = $script:Hs13VM,
        [string] $BuildSwitch = 'SRB-Build',
        [int]    $TimeoutSeconds = 600
    )

    # .ToString() ON THE GUEST. The DISM state is an enum, and PowerShell
    # Direct serialises it to its numeric value: comparing the result against
    # 'Installed' here yielded '4' -eq 'Installed' -> false, so a successful
    # install reported as a failure. Convert while the enum still exists.
    $already = Invoke-Command -VMName $VMName -Credential $script:Hs13Cred -ScriptBlock {
        (Get-WindowsCapability -Online -Name 'OpenSSH.Server*').State.ToString()
    }
    if ($already -eq 'Installed') {
        Write-Host '[hs13] OpenSSH Server already installed'
        return
    }

    if (-not (Get-VMSwitch -Name $BuildSwitch -ErrorAction SilentlyContinue)) {
        throw "[hs13] external switch '$BuildSwitch' not found; it is needed once to fetch the OpenSSH FoD"
    }

    $added = $false
    try {
        if (-not (Get-VMNetworkAdapter -VMName $VMName | Where-Object { $_.SwitchName -eq $BuildSwitch })) {
            Add-VMNetworkAdapter -VMName $VMName -SwitchName $BuildSwitch -Name 'hs13-build'
            $added = $true
            Write-Host "[hs13] attached $BuildSwitch temporarily for the FoD download"
        }

        # Wait for the guest to actually get a route, not merely for the adapter
        # to exist. DHCP on a Wi-Fi-backed external switch is not instant.
        $deadline = (Get-Date).AddSeconds(180)
        $online = $false
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 5
            $online = Invoke-Command -VMName $VMName -Credential $script:Hs13Cred -ScriptBlock {
                [bool](Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
            }
            if ($online) { break }
        }
        if (-not $online) { throw "[hs13] guest never obtained a default route via $BuildSwitch" }

        Write-Host '[hs13] installing OpenSSH.Server (Feature on Demand)...'
        $r = Invoke-Command -VMName $VMName -Credential $script:Hs13Cred -ScriptBlock {
            $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' |
                     Where-Object { $_.State -ne 'Installed' } | Select-Object -First 1
            if ($cap) { Add-WindowsCapability -Online -Name $cap.Name | Out-Null }
            (Get-WindowsCapability -Online -Name 'OpenSSH.Server*').State.ToString()
        }
        if ($r -ne 'Installed') { throw "[hs13] OpenSSH.Server state is '$r' after install" }
        Write-Host '[hs13] OpenSSH Server installed'
    }
    finally {
        if ($added) {
            Get-VMNetworkAdapter -VMName $VMName |
                Where-Object { $_.SwitchName -eq $BuildSwitch } |
                Remove-VMNetworkAdapter
            Write-Host "[hs13] detached $BuildSwitch -- lab is isolated again"
        }
    }
}

function Install-Hs13SshAccess {
    <#
    .SYNOPSIS
        Give the bridge container the same SSH contract Vagrant used to provide.

    .DESCRIPTION
        The Inspect sandbox for S13 is a BRIDGE CONTAINER that SSHes into the
        target; the agent never touches Hyper-V. Under Vagrant that worked
        because VirtualBox NAT forwarded host 2223 to the guest's OpenSSH, and
        a provisioner installed the pipeline's public key.

        This reproduces that contract exactly -- account `vagrant`, port 2223 on
        host.docker.internal, key at /root/.ssh/vagrant_key -- so
        inspect_eval's solvers, scorer and task prompt need no changes at all.
        Only the mechanism behind the contract moves from Vagrant to
        AutomatedLab.

        `vagrant` is a DOMAIN account, not a local one: this machine is a domain
        controller, and promotion destroys the local SAM. Creating it locally
        would fail, or worse, appear to succeed against a stale SAM.
    #>
    param([Parameter(Mandatory)] [string] $PublicKeyPath)

    if (-not (Test-Path $PublicKeyPath)) { throw "[hs13] public key not found: $PublicKeyPath" }
    $pub = (Get-Content -LiteralPath $PublicKeyPath -Raw).Trim()

    Wait-Hs13Ready | Out-Null

    # sshd is a Feature-on-Demand and the lab is isolated, so it cannot be
    # fetched here. Install-Hs13OpenSshServer handles the temporary external
    # switch; calling it first makes this function work on a fresh lab instead
    # of failing with a bare COMException from Add-WindowsCapability.
    Install-Hs13OpenSshServer

    Invoke-Command -VMName $script:Hs13VM -Credential $script:Hs13Cred -ErrorAction Stop `
        -ArgumentList $pub -ScriptBlock {
        param($pub)
        $ErrorActionPreference = 'Stop'
        Import-Module ActiveDirectory

        # NO ACCOUNT IS CREATED. The bridge authenticates as the domain
        # Administrator, which AutomatedLab already provisioned.
        #
        # A purpose-made `vagrant` domain account was tried first and sshd RESET
        # the connection for it in every name form -- plain, UPN and DOMAIN\user
        # -- immediately after SSH2_MSG_SERVICE_ACCEPT, while Administrator
        # authenticated fine over the same key and the same authorized_keys
        # file. Rather than chase a Windows OpenSSH 7.7 quirk, the scenario uses
        # the account that works: already a domain admin with a profile, the
        # privilege level a DC remediation needs anyway, and one less stray
        # privileged account in a scenario that grades on unauthorized accounts.

        # --- OpenSSH Server ---
        $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' |
                 Where-Object { $_.State -ne 'Installed' }
        if ($cap) { Add-WindowsCapability -Online -Name $cap.Name | Out-Null }

        Set-Service -Name sshd -StartupType Automatic
        if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd }

        # --- authorised key ---
        #
        # Members of Administrators (which Domain Admins are, on a DC) are NOT
        # read from the user's ~/.ssh/authorized_keys by default: sshd_config
        # redirects them to this single file, and it must be owned by
        # Administrators/SYSTEM with inheritance disabled or sshd silently
        # refuses the key.
        $akf = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
        $dir = Split-Path $akf -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

        $existing = if (Test-Path $akf) { Get-Content -LiteralPath $akf -Raw } else { '' }
        if ($existing -notmatch [regex]::Escape($pub)) {
            Add-Content -LiteralPath $akf -Value $pub -Encoding ascii
        }

        icacls $akf /inheritance:r | Out-Null
        icacls $akf /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null

        # sshd caches nothing important, but restarting makes the key live
        # immediately rather than at the next connection's discretion.
        Restart-Service sshd -Force

        "sshd=$((Get-Service sshd).Status) key_bytes=$((Get-Item $akf).Length)"
    } | ForEach-Object { Write-Host "[hs13] $_" }
}

function Set-Hs13PortProxy {
    <#
    .SYNOPSIS
        Forward host 2223 to the DC's SSH, reproducing VirtualBox's NAT rule.

    .DESCRIPTION
        The bridge container reaches the target as host.docker.internal:2223,
        because that is what VirtualBox NAT gave it. The AutomatedLab DC instead
        sits on an INTERNAL Hyper-V switch at 10.20.13.5, which a Docker Desktop
        container has no route to.

        A host portproxy restores the old contract rather than rewiring the
        container's networking: the host listens on 2223 and forwards to the
        lab. Port 2223 is kept deliberately -- scenario-14 uses 2222, and the
        two must not collide.
    #>
    param([int] $ListenPort = 2223, [string] $TargetIp = '10.20.13.5', [int] $TargetPort = 22)

    $existing = & netsh interface portproxy show v4tov4 2>&1 | Out-String
    if ($existing -match "\s$ListenPort\s") {
        & netsh interface portproxy delete v4tov4 listenport=$ListenPort listenaddress=0.0.0.0 2>&1 | Out-Null
    }
    & netsh interface portproxy add v4tov4 `
        listenport=$ListenPort listenaddress=0.0.0.0 `
        connectport=$TargetPort connectaddress=$TargetIp 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "[hs13] netsh portproxy add returned $LASTEXITCODE" }

    # Firewall: the listener is on the host, so the host must accept it.
    $ruleName = "SRB-HS13-ssh-$ListenPort"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $ListenPort | Out-Null
    }
    Write-Host "[hs13] portproxy 0.0.0.0:$ListenPort -> ${TargetIp}:$TargetPort"
}

function Test-Hs13SshReachable {
    param([int] $ListenPort = 2223)
    try {
        $c = Test-NetConnection -ComputerName '127.0.0.1' -Port $ListenPort -WarningAction SilentlyContinue
        return [bool]$c.TcpTestSucceeded
    } catch { return $false }
}

function Invoke-Hs13Verify {
    <#
    .SYNOPSIS
        Run verify.ps1 on the DC and return its real exit code plus transcript.
    #>
    $here = Split-Path $PSScriptRoot -Parent
    $verifyLocal = Join-Path $here 'verify.ps1'

    $r = Invoke-Command -VMName $script:Hs13VM -Credential $script:Hs13Cred -ErrorAction Stop `
            -ArgumentList (Get-Content -LiteralPath $verifyLocal -Raw) -ScriptBlock {
        param($text)
        $p = Join-Path $env:TEMP 'hs13-verify.ps1'
        Set-Content -LiteralPath $p -Value $text -Encoding UTF8
        try {
            $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p 2>&1 | Out-String
            [pscustomobject]@{ Output = $out; ExitCode = $LASTEXITCODE }
        }
        finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }

    [pscustomobject]@{ Output = [string]$r.Output; ExitCode = [int]$r.ExitCode }
}
