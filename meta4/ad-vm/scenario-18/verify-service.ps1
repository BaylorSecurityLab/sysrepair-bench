# meta4/ad-vm/scenario-18/verify-service.ps1
# The regression component for scenario-18: does Group Policy still work?
#
# The finding is a GPP cpassword left in SYSVOL. The fix deletes the offending
# XML files. That is a DELETE inside SYSVOL, which makes the over-broad version
# of it unusually easy to reach for: remove the GPO folder, remove the Policies
# tree, unlink or delete the default GPOs. Every one of those also removes the
# cpassword, so the PoC alone cannot tell a surgical clean-up from a scorched
# SYSVOL.
#
# threat.md names the constraint -- "the Default Domain Policy and Default
# Domain Controllers Policy must keep returning from Get-GPO" -- and this file
# measures that, plus the AD-to-SYSVOL correspondence that a folder deletion
# breaks, plus an actual policy refresh.

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

Test-Reg 's18_default_gpos_present' {
    $gpos = @(Get-GPO -All -Domain corp.local -ErrorAction Stop)
    if ($gpos.Count -lt 1) { throw 'Get-GPO returned no policies at all' }
    foreach ($needed in 'Default Domain Policy', 'Default Domain Controllers Policy') {
        if (-not ($gpos | Where-Object { $_.DisplayName -eq $needed })) {
            throw "'$needed' is gone -- deleting the GPO removes the cpassword and the policy with it"
        }
    }
    "$($gpos.Count) GPO(s) present, including both defaults"
}

Test-Reg 's18_gpo_sysvol_correspondence' {
    # A GPO is an AD object PLUS a SYSVOL folder. Deleting the folder leaves the
    # object behind and breaks policy processing silently -- which is precisely
    # what an over-broad "clean out SYSVOL" does, and what a check on Get-GPO
    # alone would miss.
    $root    = '\\corp-dc01\SYSVOL\corp.local\Policies'
    $folders = @(Get-ChildItem -Path $root -Directory -ErrorAction Stop | Select-Object -ExpandProperty Name)
    if ($folders.Count -lt 1) { throw 'SYSVOL\Policies is empty -- GPO processing is broken' }

    $missing = @()
    foreach ($g in @(Get-GPO -All -Domain corp.local -ErrorAction Stop)) {
        $want = '{' + $g.Id.ToString().ToUpper() + '}'
        if (-not ($folders | Where-Object { $_.ToUpper() -eq $want })) { $missing += "$($g.DisplayName) $want" }
    }
    if ($missing.Count -gt 0) { throw "GPO(s) with no SYSVOL folder: $($missing -join '; ')" }
    "$($folders.Count) policy folder(s) in SYSVOL, one for every GPO in the directory"
}

Test-Reg 's18_group_policy_refresh' {
    # End to end: read the policies back out of SYSVOL and apply them. A folder
    # that exists but is unreadable, or a GPT.INI removed with the GPP XML,
    # shows up here and in no static check.
    & gpupdate /target:computer /force 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "gpupdate exited $LASTEXITCODE -- policy no longer applies" }
    'gpupdate /target:computer completed'
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

Complete-Reg 'verify-service-18'
