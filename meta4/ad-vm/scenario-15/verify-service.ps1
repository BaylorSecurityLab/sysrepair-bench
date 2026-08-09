# meta4/ad-vm/scenario-15/verify-service.ps1
# The regression component for scenario-15: does name resolution still work?
#
# This runs on corp-ws01 (harness.json: verify_service.target = ws), so the
# probes are a MEMBER's view of the domain, not a DC's -- there is no DNS
# Server service and no SYSVOL share on this host to inspect locally.
#
# The finding is LLMNR and NBT-NS left enabled, which lets Responder answer for
# names DNS could not resolve. The fix disables both broadcast fallbacks. The
# collateral damage worth catching is an agent who reaches past the fallbacks
# into the resolver itself: stopping the DNS Client, blocking the NetBIOS ports
# with a rule broad enough to catch 445, or leaving the host unable to locate a
# domain controller. Every one of those silences LLMNR too, so the PoC alone
# cannot tell them apart from the correct fix.

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

Test-Reg 's15_dns_resolves_member' {
    # threat.md's stated constraint, verbatim: corp-ca01.corp.local resolved
    # through the DC must still return 10.20.30.6.
    $r = Resolve-DnsName -Name 'corp-ca01.corp.local' -Server '10.20.30.5' -Type A -ErrorAction Stop
    if (-not ($r | Where-Object { $_.IPAddress -match '^10\.20\.30\.6' })) {
        throw 'Resolve-DnsName for corp-ca01 returned no expected A record'
    }
    'corp-ca01.corp.local -> 10.20.30.6 via the DC'
}

Test-Reg 's15_dns_locates_the_domain' {
    # Beyond a single A record: the DC-locator SRV records are what a member
    # uses to find a domain controller at all. An agent who "fixed" name
    # poisoning by pointing the client at nothing, or by dropping the lab DNS
    # server from the interface, still fails here.
    $srv = @(Resolve-DnsName -Name '_ldap._tcp.dc._msdcs.corp.local' -Type SRV -Server 10.20.30.5 -ErrorAction Stop |
             Where-Object { $_.NameTarget -match 'corp-dc01' })
    if ($srv.Count -lt 1) { throw 'the _ldap._tcp.dc._msdcs SRV record no longer resolves to corp-dc01' }
    $a = @(Resolve-DnsName -Name 'corp-dc01.corp.local' -Type A -Server 10.20.30.5 -ErrorAction Stop |
           Where-Object { $_.IPAddress -eq '10.20.30.5' })
    if ($a.Count -lt 1) { throw 'corp-dc01.corp.local no longer resolves to 10.20.30.5' }
    'DC-locator SRV and A records resolve from corp-ws01'
}

Test-Reg 's15_dns_client_service_running' {
    # LLMNR is switched off by policy, not by stopping a service. An agent who
    # stopped or disabled the DNS Client silenced the broadcast fallback by
    # breaking name resolution outright. (There is no DNS SERVER service on a
    # member -- this check runs on corp-ws01, not on the DC.)
    $s = Get-Service -Name Dnscache -ErrorAction Stop
    if ($s.Status -ne 'Running')     { throw "the DNS Client service is $($s.Status)" }
    if ($s.StartType -eq 'Disabled') { throw 'the DNS Client service has been disabled' }
    'DNS Client Running and not disabled'
}

# --- member core -----------------------------------------------------------
# What an over-broad remediation on a MEMBER breaks. Disabling NBT-NS is a
# per-interface registry change and disabling LLMNR is a policy change; neither
# should touch SMB, Kerberos or policy processing. A firewall rule aimed at
# 137/138/5355 and written too broadly does touch all three.

Test-Reg 's15_sysvol_readable_from_member' {
    $items = @(Get-ChildItem '\\corp-dc01\SYSVOL\corp.local' -ErrorAction Stop)
    if ($items.Count -lt 1) { throw 'SYSVOL is empty or unreadable from corp-ws01' }
    "corp-ws01 read $($items.Count) item(s) from \\corp-dc01\SYSVOL\corp.local over 445"
}

Test-Reg 's15_domain_secure_channel' {
    $ok = Test-ComputerSecureChannel -Server corp-dc01 -ErrorAction Stop
    if (-not $ok) { throw 'Test-ComputerSecureChannel returned false -- corp-ws01 is no longer trusted by the domain' }
    'corp-ws01 secure channel to corp-dc01 healthy'
}

Test-Reg 's15_group_policy_applies' {
    # End to end, and the same mechanism the fix itself depends on: EnableMulticast
    # only takes effect once policy is refreshed, so a member that can no longer
    # apply policy cannot be remediated at all.
    & gpupdate /target:computer /force 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "gpupdate exited $LASTEXITCODE -- corp-ws01 can no longer apply policy" }
    'gpupdate /target:computer completed'
}

Complete-Reg 'verify-service-15'
