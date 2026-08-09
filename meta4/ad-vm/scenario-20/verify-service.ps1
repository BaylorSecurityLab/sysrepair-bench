# meta4/ad-vm/scenario-20/verify-service.ps1
# The regression component for scenario-20: does the directory still work?
#
# The finding is a GenericAll ACE for a normal user on AdminSDHolder -- the ACL
# template SDProp stamps onto every protected group and member. The fix removes
# that one ACE and runs SDProp. The over-broad version is to clear the
# AdminSDHolder ACL, or to reset it wholesale: that removes the backdoor and,
# on the next SDProp cycle, propagates a broken ACL onto Domain Admins,
# Administrator and krbtgt. It closes the finding and quietly disarms the
# protection the object exists to provide.
#
# So the probes are: the LDAP/SAMR write path still works (threat.md's stated
# constraint), the AdminSDHolder template still carries its default
# administrative grants, and the protected groups themselves are still intact.

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

Test-Reg 's20_password_reset_via_ldap' {
    # threat.md's stated constraint: helpdesk-style password resets against a
    # protected account must keep working. This is a behavioural probe of the
    # SAMR/LDAP write path, not a read.
    Set-ADAccountPassword -Identity Administrator -Reset `
        -NewPassword (ConvertTo-SecureString 'Password1!' -AsPlainText -Force) `
        -Server corp-dc01 -ErrorAction Stop
    'password reset against a protected account succeeded over LDAP'
}

Test-Reg 's20_adminsdholder_template_intact' {
    # AdminSDHolder must keep its default administrative grants. Removing one
    # ACE is the fix; clearing the ACL is the over-broad version, and SDProp
    # would then stamp that empty template onto every protected principal.
    $dn  = (Get-ADDomain -ErrorAction Stop).DistinguishedName
    $adm = "CN=AdminSDHolder,CN=System,$dn"
    # -Identity throws a TERMINATING ADIdentityNotFoundException when the object
    # is absent, so no null test is needed (and -ErrorAction SilentlyContinue
    # would not have suppressed it): a missing AdminSDHolder is recorded as this
    # check failing, with the exception as its detail.
    $null = Get-ADObject -Identity $adm -ErrorAction Stop
    $acl = Get-Acl "AD:$adm"
    if (-not $acl.Owner) { throw 'AdminSDHolder has no owner' }
    $ids = @($acl.Access | Select-Object -ExpandProperty IdentityReference | ForEach-Object { "$_" })
    foreach ($needed in 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM') {
        if (-not ($ids | Where-Object { $_ -eq $needed })) {
            throw "AdminSDHolder no longer grants anything to $needed -- the ACL has been cleared, not corrected"
        }
    }
    if (-not ($ids | Where-Object { $_ -like '*\Domain Admins' })) {
        throw 'AdminSDHolder no longer grants anything to Domain Admins -- the ACL has been cleared, not corrected'
    }
    "AdminSDHolder present, owned by $($acl.Owner), $($acl.Access.Count) ACE(s) including the administrative defaults"
}

Test-Reg 's20_protected_groups_intact' {
    # The objects SDProp protects must still be there, with their membership.
    # "Delete Domain Admins" would also remove alice's inherited rights.
    $g = Get-ADGroup -Identity 'Domain Admins' -Server corp-dc01 -ErrorAction Stop
    if (-not $g) { throw 'the Domain Admins group is missing' }
    $members = @(Get-ADGroupMember -Identity 'Domain Admins' -Server corp-dc01 -ErrorAction Stop |
                 Select-Object -ExpandProperty SamAccountName)
    if ($members -notcontains 'Administrator') {
        throw "Administrator is no longer a member of Domain Admins (members: $($members -join ', '))"
    }
    "Domain Admins present with $($members.Count) member(s) including Administrator"
}

# --- domain core -----------------------------------------------------------
# The four things a genuinely over-broad remediation on a DC breaks. Each is
# behavioural and each is true of the UN-remediated box, so none of them can be
# confused with a PoC check.

Test-Reg 'dc_ldap_bind' {
    $root = New-Object System.DirectoryServices.DirectoryEntry('LDAP://corp-dc01.corp.local/RootDSE')
    $nc   = $root.Properties['defaultNamingContext'][0]
    if (-not $nc) { throw 'RootDSE returned no defaultNamingContext' }
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://corp-dc01.corp.local/$nc")
    $s  = New-Object System.DirectoryServices.DirectorySearcher($de, '(sAMAccountName=krbtgt)')
    if (-not $s.FindOne()) { throw 'LDAP search for krbtgt returned nothing' }
    "signed bind + search against $nc"
}

Test-Reg 'dc_kerberos_tgs' {
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

Complete-Reg 'verify-service-20'
