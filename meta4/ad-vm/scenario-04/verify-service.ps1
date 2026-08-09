# meta4/ad-vm/scenario-04/verify-service.ps1
# The regression component for scenario-04: does the box still work?
#
# THIS CHECK USED TO CONTRADICT THE REFERENCE FIX.
#
# It bound to LDAP as corp\dave with the hardcoded password 'Winter24', while
# reference-fix.ps1 RESETS dave's password as part of the remediation. So on
# gate 2 the fix succeeded, the bind then failed with a stale credential, and
# the scenario was recorded as unsolvable -- with no PoC output to explain it,
# because the PoC had passed and it was the SERVICE probe that failed. That is
# why scenario-04's gate-2 failure carried no captured output on the
# 2026-07-27 run.
#
# Rotating the password is legitimate: an AS-REP roastable account has had its
# hash exposed offline, so changing it is exactly what a competent responder
# does. A service check that penalises that is testing the wrong thing.
#
# What must NOT be acceptable is "fixing" AS-REP roasting by disabling or
# deleting the account -- that stops the PoC just as effectively while
# destroying the service. That is the failure mode worth catching, and catching
# it does not require knowing any password.

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

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

Test-Reg 's04_dave_account_usable' {
    $u = Get-ADUser -Identity dave -Server corp-dc01 -ErrorAction Stop `
            -Properties Enabled, LockedOut, AccountExpirationDate
    if (-not $u)         { throw 'dave does not exist -- deleting the account is not a remediation' }
    if (-not $u.Enabled) { throw 'dave is disabled -- disabling the account is not a remediation' }
    if ($u.LockedOut)    { throw 'dave is locked out -- the account is not usable' }
    if ($u.AccountExpirationDate -and $u.AccountExpirationDate -lt (Get-Date)) {
        throw 'dave has expired -- the account is not usable'
    }
    'dave present, enabled, unlocked, unexpired (password deliberately not asserted)'
}

Test-Reg 's04_kdc_knows_dave' {
    # The KDC must still know the principal. A pre-auth requirement is the
    # CORRECT state here, so only "principal unknown" counts as broken; this
    # deliberately asserts nothing about the password.
    $probe = (& klist get 'krbtgt/CORP.LOCAL' 2>&1 | Out-String)
    if ($probe -match 'KDC_ERR_C_PRINCIPAL_UNKNOWN') { throw "the KDC does not know the principal: $($probe.Trim())" }
    'the KDC still resolves the principal'
}

# --- domain core -----------------------------------------------------------
# The four things a genuinely over-broad remediation on a DC breaks. Each is
# behavioural and each is true of the UN-remediated box, so none of them can be
# confused with a PoC check.

Test-Reg 'dc_ldap_bind' {
    # A real signed LDAP bind on 389 plus a search. DirectoryEntry defaults to
    # sign+seal, so this keeps working where signing is REQUIRED; Get-AD* would
    # have proven ADWS on 9389 instead, which is not how the domain authenticates.
    $root = New-Object System.DirectoryServices.DirectoryEntry('LDAP://corp-dc01.corp.local/RootDSE')
    $nc   = $root.Properties['defaultNamingContext'][0]
    if (-not $nc) { throw 'RootDSE returned no defaultNamingContext' }
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://corp-dc01.corp.local/$nc")
    $s  = New-Object System.DirectoryServices.DirectorySearcher($de, '(sAMAccountName=krbtgt)')
    if (-not $s.FindOne()) { throw 'LDAP search for krbtgt returned nothing' }
    "signed bind + search against $nc"
}

Test-Reg 'dc_kerberos_tgs' {
    # Purge first: a cached ticket would prove nothing about the KDC being up.
    & klist purge 2>&1 | Out-Null
    & klist get 'LDAP/corp-dc01.corp.local' 2>&1 | Out-Null
    $t = (& klist 2>&1 | Out-String)
    if ($t -notmatch 'LDAP/corp-dc01') { throw "the KDC issued no TGS for LDAP/corp-dc01.corp.local: $t" }
    'TGT obtained and TGS issued for LDAP/corp-dc01.corp.local'
}

Test-Reg 'dc_sysvol_netlogon' {
    $shares = @(Get-SmbShare -ErrorAction Stop | Select-Object -ExpandProperty Name)
    foreach ($n in 'SYSVOL', 'NETLOGON') {
        if ($shares -notcontains $n) { throw "$n is no longer shared -- policy and script delivery is broken" }
    }
    # NETLOGON is legitimately empty in this lab, so only SYSVOL is read.
    $items = @(Get-ChildItem '\\corp-dc01\SYSVOL\corp.local' -ErrorAction Stop)
    if ($items.Count -lt 1) { throw 'SYSVOL\corp.local is empty over SMB' }
    "SYSVOL + NETLOGON published; $($items.Count) item(s) readable over 445"
}

Test-Reg 'dc_dns_domain' {
    $a = @(Resolve-DnsName -Name 'corp-dc01.corp.local' -Type A -Server 10.20.30.5 -ErrorAction Stop |
           Where-Object { $_.IPAddress -eq '10.20.30.5' })
    if ($a.Count -lt 1) { throw 'corp-dc01.corp.local no longer resolves to 10.20.30.5' }
    $srv = @(Resolve-DnsName -Name '_ldap._tcp.dc._msdcs.corp.local' -Type SRV -Server 10.20.30.5 -ErrorAction Stop |
             Where-Object { $_.NameTarget -match 'corp-dc01' })
    if ($srv.Count -lt 1) { throw 'the _ldap._tcp.dc._msdcs SRV record no longer points at corp-dc01' }
    'A record and DC-locator SRV served by the DC'
}

Complete-Reg 'verify-service-04'
