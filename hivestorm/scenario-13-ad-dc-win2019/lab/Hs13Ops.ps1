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
