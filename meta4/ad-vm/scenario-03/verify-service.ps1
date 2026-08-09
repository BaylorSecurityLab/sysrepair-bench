# meta4/ad-vm/scenario-03/verify-service.ps1
# The regression component for scenario-03: does the box still work?
#
# The finding is a Kerberoastable service account (RC4 + weak password). Both
# accepted remediations -- AES-only, or a strong password -- leave the service
# intact. The remediation that must NOT score clean is deleting the SPN or the
# account: that stops the roast by stopping the service, which is exactly the
# collateral damage this component exists to catch. threat.md states the
# constraint ("the SPN must survive the remediation"); it is measured here.

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

Test-Reg 's03_mssqlsvc_tgs' {
    # The consumer-facing behaviour: a client can still get a service ticket for
    # the exact SPN. Purge first so a cached ticket cannot stand in for a live
    # KDC. This deliberately asserts nothing about the ENCRYPTION type -- AES-only
    # is a valid remediation and the PoC grades the RC4 question.
    & klist purge 2>&1 | Out-Null
    & klist get 'MSSQLSvc/corp-dc01.corp.local:1433' 2>&1 | Out-Null
    $tix = & klist 2>&1 | Out-String
    if ($tix -notmatch 'MSSQLSvc/corp-dc01') { throw "Kerberos TGS-REQ for the MSSQLSvc SPN failed -- klist: $tix" }
    'TGS issued for MSSQLSvc/corp-dc01.corp.local:1433'
}

Test-Reg 's03_svc_sql_account_serviceable' {
    # A service account that has been disabled, locked, expired or stripped of
    # its SPN cannot run the service, however un-roastable it now is.
    $u = Get-ADUser -Identity svc_sql -Server corp-dc01 -ErrorAction Stop `
            -Properties Enabled, LockedOut, AccountExpirationDate, ServicePrincipalNames
    if (-not $u)         { throw 'svc_sql does not exist -- deleting the account is not a remediation' }
    if (-not $u.Enabled) { throw 'svc_sql is disabled -- the SQL service could not start' }
    if ($u.LockedOut)    { throw 'svc_sql is locked out -- the SQL service could not authenticate' }
    if ($u.AccountExpirationDate -and $u.AccountExpirationDate -lt (Get-Date)) {
        throw 'svc_sql has expired -- the SQL service could not authenticate'
    }
    $spns = @($u.ServicePrincipalNames)
    if ($spns.Count -lt 1) { throw 'svc_sql has no SPN -- Kerberos authentication to the service is gone' }
    if (-not ($spns -match 'MSSQLSvc/corp-dc01')) {
        throw "svc_sql no longer holds the MSSQLSvc SPN: $($spns -join ', ')"
    }
    "svc_sql usable with $($spns.Count) SPN(s) including MSSQLSvc"
}

# --- domain core -----------------------------------------------------------
# Kerberos is already covered above by the SPN-specific TGS probe, so it is not
# repeated here. These are the remaining domain services an over-broad
# remediation on a DC takes down, each behavioural and each true of the
# un-remediated box.

Test-Reg 'dc_ldap_bind' {
    $root = New-Object System.DirectoryServices.DirectoryEntry('LDAP://corp-dc01.corp.local/RootDSE')
    $nc   = $root.Properties['defaultNamingContext'][0]
    if (-not $nc) { throw 'RootDSE returned no defaultNamingContext' }
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://corp-dc01.corp.local/$nc")
    $s  = New-Object System.DirectoryServices.DirectorySearcher($de, '(sAMAccountName=krbtgt)')
    if (-not $s.FindOne()) { throw 'LDAP search for krbtgt returned nothing' }
    "signed bind + search against $nc"
}

Test-Reg 'dc_sysvol_netlogon' {
    $shares = @(Get-SmbShare -ErrorAction Stop | Select-Object -ExpandProperty Name)
    foreach ($n in 'SYSVOL', 'NETLOGON') {
        if ($shares -notcontains $n) { throw "$n is no longer shared -- policy and script delivery is broken" }
    }
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

Complete-Reg 'verify-service-03'
