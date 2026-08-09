# meta4/ad-vm/scenario-02/verify-service.ps1
# The regression component for scenario-02: does the box still work?
#
# The finding is ms-DS-MachineAccountQuota left at the Windows default of 10,
# which hands any authenticated user the machine account NoPac needs. The
# reference remediation sets it to 0 and rests on a claim -- "legitimate domain
# joins are performed by delegated accounts, which are unaffected". That claim
# is MEASURED below rather than assumed: an agent that closes the finding by
# denying computer-object creation outright, or by breaking the Computers
# container, breaks domain joins for everyone and must not score clean.

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

Test-Reg 's02_member_computer_objects_readable' {
    # threat.md's stated constraint: Get-ADComputer against the DC must keep
    # working for legitimate Domain Admins, and the members must stay enabled.
    foreach ($n in 'corp-ca01', 'corp-ws01') {
        $c = Get-ADComputer -Identity $n -Server corp-dc01 -Properties Enabled -ErrorAction Stop
        if (-not $c)         { throw "$n has no computer object -- the member is no longer joined" }
        if (-not $c.Enabled) { throw "$n computer object is disabled -- domain-join broken" }
    }
    $dc = Get-ADComputer -Identity 'corp-dc01' -Server corp-dc01 -ErrorAction Stop
    if ($dc.ObjectClass -ne 'computer') { throw 'the DC computer object is missing' }
    'corp-ca01, corp-ws01 and corp-dc01 all readable and enabled'
}

Test-Reg 's02_delegated_computer_creation' {
    # MachineAccountQuota does not apply to principals holding Create Child on
    # the container, so a Domain Admin must still be able to create a computer
    # account after the quota is zeroed. This is the behavioural test of the
    # claim the remediation rests on: an agent that revokes computer creation
    # wholesale, or removes Create Child from the Computers container, stops
    # NoPac and stops domain joins with it.
    $dn   = (Get-ADDomain -ErrorAction Stop).DistinguishedName
    $name = 'srb-svcprobe-02'

    # -Filter, never -Identity, for the lookups that are allowed to find
    # nothing. ADIdentityNotFoundException from Get-AD*  -Identity is a
    # TERMINATING error, which -ErrorAction SilentlyContinue does not suppress;
    # written the obvious way, the clean-up for a leftover object that is not
    # there fails the check it was meant to protect. Measured on the live DC.
    Get-ADComputer -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue |
        Remove-ADComputer -Confirm:$false -ErrorAction SilentlyContinue
    try {
        New-ADComputer -Name $name -SAMAccountName "$name`$" -Path "CN=Computers,$dn" `
            -Enabled $true -ErrorAction Stop
        $c = @(Get-ADComputer -Filter "Name -eq '$name'" -ErrorAction Stop)
        if ($c.Count -lt 1) { throw 'the computer account did not appear after creation' }
    }
    finally {
        Get-ADComputer -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue |
            Remove-ADComputer -Confirm:$false -ErrorAction SilentlyContinue
    }
    'a delegated (Domain Admin) computer-account create + delete round trip succeeded'
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

Complete-Reg 'verify-service-02'
