# meta4/ad-vm/scenario-13/verify-service.ps1
# The regression component for scenario-13: does corp-ws01 still work?
#
# The finding is SMB signing not required on the member. Requiring it is a
# one-line change to the running configuration; the over-broad versions --
# stopping LanmanServer, disabling SMB2, or firewalling 445 -- also stop the
# relay, and threat.md rules all three out by name. Each is measured here
# rather than assumed, and the member's ability to keep participating in the
# domain (secure channel, policy) is measured with them, because a host that
# no longer applies policy is not a working member however healthy its SMB
# stack looks.

$ErrorActionPreference = 'Stop'

# --- regression recorder ---------------------------------------------------
# verify-service.ps1 is shipped into the guest ON ITS OWN by
# Invoke-Command -FilePath, so lib/verifylib.ps1 does not exist inside the VM
# and cannot be dot-sourced. This is the smallest self-contained equivalent:
# the same JSONL wire format, regression records only. Invoke-ScenarioVerify
# counts those records to fill reg_total / reg_failed, which is what turns the
# collateral-damage rate into a measurement over several probes instead of one.
#
# Two rules keep it honest under $ErrorActionPreference = 'Stop':
#   * every probe runs inside Test-Reg's try/catch, so one failing cmdlet
#     records a FAIL instead of killing the script and taking the remaining
#     checks with it;
#   * nothing aborts early, so reg_total is a constant of the scenario rather
#     than a function of where the script happened to die.
$script:RegAll = @()
$script:RegBad = @()

function Add-Reg {
    param([string] $Id, [bool] $Ok, [string] $Detail = '')
    $script:RegAll += $Id
    if (-not $Ok) { $script:RegBad += $Id }
    $d = "$Detail" -replace '\\', '\\' -replace '"', '\"' -replace "`r", '' -replace "`n", ' '
    if ($d.Length -gt 240) { $d = $d.Substring(0, 240) }
    Write-Host ("  [{0}] (regression) {1}{2}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Id, $(if ($d) { ": $d" } else { '' }))
    Write-Output ('{{"id":"{0}","kind":"regression","pass":{1},"detail":"{2}"}}' -f $Id, $(if ($Ok) { 'true' } else { 'false' }), $d)
}

function Test-Reg {
    # PASS unless the probe throws, returns $false, or leaves a native command
    # with a non-zero exit code. A string return becomes the record's detail.
    param([string] $Id, [scriptblock] $Probe)
    $global:LASTEXITCODE = 0
    try {
        $out  = @(& $Probe)
        if ($global:LASTEXITCODE -ne 0) { Add-Reg $Id $false "native command exited $global:LASTEXITCODE"; return }
        $last = if ($out.Count) { $out[-1] } else { $null }
        if ($last -is [bool] -and -not $last) { Add-Reg $Id $false 'probe returned false'; return }
        if ($last -is [string]) { Add-Reg $Id $true $last; return }
        Add-Reg $Id $true
    } catch {
        Add-Reg $Id $false $_.Exception.Message
    }
}

function Complete-Reg {
    # Write-Error is TERMINATING here, and that is deliberate: `exit 1` inside a
    # PowerShell Direct script is invisible to Invoke-Command -FilePath, so a
    # thrown error is the only way this side can report failure to the harness.
    param([string] $Tag)
    if ($script:RegBad.Count -gt 0) {
        Write-Error ("[{0}] {1} of {2} regression check(s) FAILED: {3}" -f `
            $Tag, $script:RegBad.Count, $script:RegAll.Count, ($script:RegBad -join ', '))
        exit 1
    }
    Write-Host ("[{0}] all {1} regression check(s) passed -- service HEALTHY" -f $Tag, $script:RegAll.Count)
    exit 0
}
# --- end recorder ----------------------------------------------------------

Test-Reg 's13_smb_server_serving' {
    # Service Running, SMB2 still on, AND 445 genuinely listening. The first two
    # are configuration; the third is the only one that catches a host firewalled
    # into silence with its service still nominally healthy.
    $svc = Get-Service -Name LanmanServer -ErrorAction Stop
    if ($svc.Status -ne 'Running') { throw "LanmanServer is $($svc.Status) -- disabling the service is not a remediation" }

    $cfg = Get-SmbServerConfiguration -ErrorAction Stop
    if (-not $cfg.EnableSMB2Protocol) { throw 'SMB2 is disabled on corp-ws01 -- the file service is broken' }

    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -ExpandProperty LocalPort -Unique)
    if ($listen -notcontains 445) { throw 'nothing is listening on TCP 445 -- corp-ws01 serves no SMB' }

    'LanmanServer Running, SMB2 enabled, TCP 445 listening'
}

Test-Reg 's13_sysvol_readable_from_member' {
    # The member's SMB CLIENT half, and the thing GPO processing depends on.
    $items = @(Get-ChildItem '\\corp-dc01\SYSVOL\corp.local' -ErrorAction Stop)
    if ($items.Count -lt 1) { throw 'SYSVOL is empty or unreadable from corp-ws01 -- GPO processing would fail' }
    "corp-ws01 read $($items.Count) item(s) from \\corp-dc01\SYSVOL\corp.local"
}

Test-Reg 's13_domain_secure_channel' {
    $ok = Test-ComputerSecureChannel -Server corp-dc01 -ErrorAction Stop
    if (-not $ok) { throw 'Test-ComputerSecureChannel returned false -- corp-ws01 is no longer trusted by the domain' }
    'corp-ws01 secure channel to corp-dc01 healthy'
}

Test-Reg 's13_group_policy_applies' {
    # End to end: locate a DC, authenticate, read SYSVOL over the very SMB stack
    # the remediation touched, and apply policy. If signing were required on one
    # side only, or 445 were blocked, this is where it shows.
    & gpupdate /target:computer /force 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "gpupdate exited $LASTEXITCODE -- corp-ws01 can no longer apply policy" }
    'gpupdate /target:computer completed'
}

Complete-Reg 'verify-service-13'
