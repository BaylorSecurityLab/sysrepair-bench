# meta4/ad-vm/scenario-06/verify-service.ps1
# The regression component for scenario-06: does the box still work?
#
# The finding is a DCSync grant to a non-admin. The remediation removes two
# extended-right ACEs from the domain head, and the failure mode worth catching
# is an over-broad ACL edit: resetting the domain DACL wholesale, or stripping
# every replication ACE, closes the finding and breaks the directory with it.
#
# The DRS probe below used to run `repadmin /showrepl /csv` and require
# 'CN=Schema' or 'CN=Configuration' in the output. On a healthy lab it failed:
# /showrepl reports inbound replication PARTNERS and corp.local is a SINGLE-DC
# forest, so it has none. /showobjmeta queries replication metadata for a
# specific object over the same DRS interface and works on a single DC.

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

Test-Reg 's06_drs_replication_interface' {
    # DRS metadata query for the domain root -- exercises the replication
    # interface DCSync abuses, rather than the (empty) partner list.
    $dn   = (Get-ADDomain -ErrorAction Stop).DistinguishedName
    $meta = & repadmin /showobjmeta corp-dc01 "$dn" 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "repadmin /showobjmeta exit=$LASTEXITCODE output=$meta" }
    if ($meta -notmatch 'Loc\.USN|Originating') {
        throw "repadmin /showobjmeta returned no replication metadata: $meta"
    }
    'DRS answered a metadata query for the domain head'
}

Test-Reg 's06_naming_contexts' {
    $ncs = (Get-ADRootDSE -ErrorAction Stop).namingContexts
    foreach ($needle in 'CN=Schema', 'CN=Configuration') {
        if (-not ($ncs -match [regex]::Escape($needle))) { throw "naming context '$needle' absent from RootDSE" }
    }
    "$(@($ncs).Count) naming context(s) enumerable"
}

Test-Reg 's06_default_replication_rights_intact' {
    # The narrow fix removes alice's two ACEs and nothing else. A blunt one --
    # `dsacls /resetDefaultDACL` on the domain head, or "delete every
    # replication ACE" -- also closes the finding and takes replication with
    # it. These two grants are Windows defaults, so this passes on the
    # un-remediated box and after the reference fix, and fails only on a
    # remediation that reached too far.
    $dn = (Get-ADDomain -ErrorAction Stop).DistinguishedName
    $getChanges    = [Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    $getChangesAll = [Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

    $aces = @((Get-Acl "AD:$dn").Access | Where-Object { $_.ActiveDirectoryRights -match 'ExtendedRight' })

    $edc = @($aces | Where-Object {
        $_.ObjectType -eq $getChanges -and $_.IdentityReference.Value -like '*\ENTERPRISE DOMAIN CONTROLLERS' })
    if ($edc.Count -lt 1) {
        throw 'ENTERPRISE DOMAIN CONTROLLERS no longer holds DS-Replication-Get-Changes on the domain head'
    }

    $dcs = @($aces | Where-Object {
        $_.ObjectType -eq $getChangesAll -and $_.IdentityReference.Value -like '*\Domain Controllers' })
    if ($dcs.Count -lt 1) {
        throw 'the Domain Controllers group no longer holds DS-Replication-Get-Changes-All on the domain head'
    }
    'default replication grants for ENTERPRISE DOMAIN CONTROLLERS and Domain Controllers still present'
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

Complete-Reg 'verify-service-06'
