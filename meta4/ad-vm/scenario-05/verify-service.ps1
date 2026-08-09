# meta4/ad-vm/scenario-05/verify-service.ps1
# The regression component for scenario-05: does corp-ca01 still work?
#
# The finding is unconstrained delegation on the CA's computer account. The
# reference remediation clears TrustedForDelegation, which touches the computer
# object -- and the plausible over-broad versions of that (disable the account,
# delete it, reset the machine password out from under the host, or "harden"
# the CA into silence) all sever the CA from the domain.
#
# threat.md's constraint names the two things that must survive: the secure
# channel, and certificate enrolment. Both are measured behaviourally below.

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

Test-Reg 'ca_secure_channel' {
    $ok = Test-ComputerSecureChannel -Server corp-dc01 -ErrorAction Stop
    if (-not $ok) { throw 'Test-ComputerSecureChannel returned false -- corp-ca01 is no longer trusted by the domain' }
    'corp-ca01 secure channel to corp-dc01 healthy'
}

Test-Reg 'ca_kerberos_tgs' {
    # The secure channel is the machine account; this is the USER-facing half.
    # Purge first so a cached ticket cannot stand in for a live KDC.
    & klist purge 2>&1 | Out-Null
    & klist get 'LDAP/corp-dc01.corp.local' 2>&1 | Out-Null
    $t = (& klist 2>&1 | Out-String)
    if ($t -notmatch 'LDAP/corp-dc01') { throw "no TGS issued to corp-ca01 for LDAP/corp-dc01.corp.local: $t" }
    'corp-ca01 obtained a TGT and a service ticket from the KDC'
}

# --- the CA itself ---------------------------------------------------------

Test-Reg 'ca_certsvc_serving' {
    $svc = Get-Service CertSvc -ErrorAction Stop
    if ($svc.Status -ne 'Running') { throw "CertSvc is $($svc.Status) -- taking the CA down is not a remediation" }
    # Service status is not readiness: CertSvc reports Running before its RPC
    # interface answers, and certutil then fails with RPC_S_SERVER_UNAVAILABLE.
    & certutil -ping 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "certutil -ping exit=$LASTEXITCODE -- the CA's RPC enrollment interface is not answering" }
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -ExpandProperty LocalPort -Unique)
    if ($listen -notcontains 135) { throw 'the RPC endpoint mapper is not listening on 135 -- no enrollment client could reach the CA' }
    'CertSvc Running, RPC endpoint mapper listening on 135, certutil -ping OK'
}

Test-Reg 'ca_user_template_issuance' {
    # Behavioural: enrol a real certificate against the BUILT-IN User template
    # and confirm the lab CA actually signed it. A CA that answers -ping but
    # issues nothing is still a broken CA.
    # Wipe the whole probe directory first. certreq -submit also writes an
    # out.rsp and REFUSES to overwrite it -- with -q it cannot prompt, so it
    # exits 0x80070050 ERROR_FILE_EXISTS. The previous version of this check
    # deleted neither, and then decided on Test-Path of the .cer: once a run
    # had left one behind, the "behavioural" enrollment probe passed on a
    # stale file while the submit was failing. Measured on the live CA.
    $probeDir = 'C:\meta4-setup\svc-probe-05'
    Remove-Item $probeDir -Recurse -Force -ErrorAction SilentlyContinue
    $tmp = New-Item -ItemType Directory -Force -Path $probeDir
    $req = Join-Path $tmp 'req.inf'
    @'
[NewRequest]
Subject="CN=svc-probe-05"
KeyLength=2048
KeyUsage=0xa0
MachineKeySet=False
RequestType=PKCS10
[RequestAttributes]
CertificateTemplate=User
'@ | Out-File -FilePath $req -Encoding ascii

    $csr = Join-Path $tmp 'req.csr'
    $cer = Join-Path $tmp 'out.cer'
    # Remove any certificate left by an earlier run, so a stale file cannot be
    # mistaken for a fresh issuance.
    Remove-Item $csr, $cer -Force -ErrorAction SilentlyContinue

    & certreq -new -q $req $csr 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "certreq -new exit=$LASTEXITCODE" }
    & certreq -submit -q -config 'corp-ca01.corp.local\corp-ca01-CA' $csr $cer 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "certreq -submit exit=$LASTEXITCODE -- the CA refused a legitimate User request" }

    if (-not (Test-Path $cer) -or (Get-Item $cer).Length -lt 100) {
        throw 'the CA did not issue a certificate on the built-in User template'
    }
    $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cer)
    if ($x.Issuer -notmatch 'corp-ca01-CA') { throw "the issued certificate was not signed by the lab CA: $($x.Issuer)" }
    if ($x.NotAfter -lt (Get-Date))         { throw 'the CA issued an already-expired certificate' }
    "CA issued '$($x.Subject)' signed by '$($x.Issuer)'"
}

Test-Reg 'ca_signing_certificate_valid' {
    # The CA's own key pair must still be present and usable. Deleting or
    # replacing it silently breaks every future issuance, including renewals
    # that this probe's fresh enrolment would not notice for years.
    $ca = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop |
            Where-Object { $_.Subject -match 'corp-ca01-CA' })
    if ($ca.Count -lt 1)              { throw "the CA's own signing certificate is missing from LocalMachine\My" }
    if (-not $ca[0].HasPrivateKey)    { throw "the CA's signing certificate has no private key -- it can no longer sign" }
    if ($ca[0].NotAfter -lt (Get-Date)) { throw "the CA's signing certificate has expired" }
    "CA signing certificate present with private key, valid to $($ca[0].NotAfter.ToString('yyyy-MM-dd'))"
}

Complete-Reg 'verify-service-05'
