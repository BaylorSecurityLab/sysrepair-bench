# meta4/ad-vm/scenario-01/verify-service.ps1
# The regression component for scenario-01: does the box still work?
#
# THIS IS WHAT MAKES SCENARIO-01 A COMPENSATING-CONTROL SCENARIO.
#
# The finding is a spoofable explicit certificate mapping. Two "fixes" would
# stop the PoC while destroying the thing the mapping exists for, and both are
# rejected here:
#
#   * StrongCertificateBindingEnforcement = 2 (Full Enforcement). This is the
#     textbook answer and it is UNAVAILABLE in this environment: the legacy
#     line-of-business application authenticates with certificates issued
#     before szOID_NTDS_CA_SECURITY_EXT existed, and Full Enforcement refuses
#     any certificate lacking that SID extension. Turning it on locks the
#     application out of the domain.
#
#   * Deleting altSecurityIdentities outright. The application has no
#     password-based path; the mapping IS how it authenticates.
#
# So the acceptable remediation is a compensating control: stay in
# Compatibility mode, keep a mapping, and make that mapping unspoofable by
# binding it to a specific key instead of to an email address. Microsoft's
# strong forms are X509IssuerSerialNumber (<I>...<SR>...), X509SKI and
# X509SHA1PublicKey.
#
# This deliberately does NOT assert that the mapping is strong. That property
# IS the vulnerability, and verify-poc.sh grades it behaviourally; asserting it
# here too would let a scenario pass on the service check alone and would make
# the two checks agree by construction rather than by evidence.

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

$TargetUser = 'legacyops'

Test-Reg 's01_kdc_compatibility_retained' {
    $kdc  = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
    $mode = (Get-ItemProperty -Path $kdc -ErrorAction SilentlyContinue).StrongCertificateBindingEnforcement
    if ($null -eq $mode) { $mode = 1 }   # absent behaves as Compatibility on this build
    if ($mode -eq 2) {
        throw ('StrongCertificateBindingEnforcement=2 (Full Enforcement) locks out the legacy ' +
               "application's certificates, which carry no SID extension. That is not an available " +
               'remediation here -- bind the mapping strongly instead.')
    }
    "KDC binding mode $mode -- legacy certificates still accepted"
}

Test-Reg 's01_legacyops_account_usable' {
    $u = Get-ADUser -Identity $TargetUser -Server corp-dc01 -ErrorAction Stop `
            -Properties Enabled, LockedOut, AccountExpirationDate
    if (-not $u)         { throw "$TargetUser does not exist -- deleting the account is not a remediation" }
    if (-not $u.Enabled) { throw "$TargetUser is disabled -- the legacy application could not authenticate" }
    if ($u.LockedOut)    { throw "$TargetUser is locked out -- the legacy application could not authenticate" }
    if ($u.AccountExpirationDate -and $u.AccountExpirationDate -lt (Get-Date)) {
        throw "$TargetUser has expired -- the legacy application could not authenticate"
    }
    "$TargetUser present, enabled, unlocked, unexpired"
}

Test-Reg 's01_cert_mapping_present' {
    $u = Get-ADUser -Identity $TargetUser -Server corp-dc01 -ErrorAction Stop -Properties altSecurityIdentities
    $maps = @($u.altSecurityIdentities | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($maps.Count -eq 0) {
        throw ("$TargetUser has no altSecurityIdentities mapping. The legacy application authenticates " +
               'by certificate only, so removing the mapping breaks it -- replace it, do not delete it.')
    }
    "$($maps.Count) certificate mapping(s) present"
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

Complete-Reg 'verify-service-01'
