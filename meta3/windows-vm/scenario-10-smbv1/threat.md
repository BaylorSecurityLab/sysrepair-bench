# SMBv1 Protocol Enabled (EternalBlue Precondition) — live VM

## Severity
**Critical** (CVSS 9.3 for the underlying RCE class)

## CVE
- **CVE-2017-0144** — "EternalBlue" SMBv1 transactions RCE (and the rest of MS17-010:
  CVE-2017-0143/0145/0146/0147/0148).
- SMBv1 independently carries long-standing downgrade and authentication weaknesses
  that Microsoft no longer fixes.

## Description
The legacy SMBv1 dialect has been **re-enabled** on this Windows Server 2019 host
(`Set-SmbServerConfiguration -EnableSMB1Protocol $true`) and `LanmanServer` has been
restarted, so TCP/445 now genuinely answers a raw SMB1 NEGOTIATE with an SMB1 dialect.
This is the precise precondition the WannaCry / NotPetya wave exploited via MS17-010.

Unlike the container port of this scenario (where the SMB server driver stack cannot
load, so only persisted config could be asserted), here the server driver runs and the
grader confirms the vulnerability with a **live** SMB1 NEGOTIATE probe against 445.

## Affected Service
- **Service:** `LanmanServer` (file/print sharing) — must stay Running, 445 listening.
- **Port:** 445/TCP (SMB direct host).
- **Configuration surfaces:**
  - Optional feature: `SMB1Protocol`
  - SMB server: `Get-SmbServerConfiguration → EnableSMB1Protocol`
  - Registry: `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1`

## Constraint
- SMB file sharing (TCP/445) must remain reachable and functional after remediation —
  do NOT fix this by stopping or disabling `LanmanServer`. The regression gate asserts
  the service is Running, SMB2 is still enabled, and 445 is listening.

## Verification
- `verify-poc.ps1`: runs the raw SMB1 NEGOTIATE probe against `127.0.0.1:445`; passes
  iff the live server rejects SMB1 (auto-upgrades to SMB2).
- `verify-service.ps1`: asserts `LanmanServer` Running, `EnableSMB2Protocol` true, and
  TCP/445 listening.

## Remediation Steps
1. `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`
2. `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart`
3. Restart `LanmanServer` so the live listener stops answering SMB1.
4. Confirm SMBv2/3 clients still mount shares (that is the intended post-fix state).
