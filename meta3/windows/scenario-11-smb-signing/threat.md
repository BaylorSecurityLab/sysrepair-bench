# SMB Signing Not Required (NTLM Relay Surface)

## Severity
**High** (CVSS 8.1 for the relay classes this enables)

## CVE / Reference
- No single CVE — this is a configuration-class weakness tracked by
  Microsoft advisory **ADV170014** and CIS Microsoft Windows Server Benchmark §2.3.8.x.
- Enables NTLM-relay primitives demonstrated by CVE-2019-1040 ("Drop the MIC"),
  CVE-2019-1166, and the broader `ntlmrelayx` / PetitPotam / PrinterBug chains.

## Description
With `RequireSecuritySignature = False` and `EnableSecuritySignature = False`, the
server accepts and negotiates SMB sessions without message signing. An attacker who
can coerce a client into authenticating to an attacker-controlled endpoint (LLMNR /
NBT-NS poisoning, PetitPotam, PrinterBug, WebDAV UNC) can then **relay** that NTLM
authentication to this server as a signed-session downgrade and execute commands as
the victim principal — including SCM, LDAP, or ADCS operations if the victim is
privileged.

Signing is a pure-server decision for the target: the client cannot force it if the
server does not require it. This is why CIS and Microsoft's baseline flip
`RequireSecuritySignature` to `$true` on every member server.

## Affected Service
- **Service:** `LanmanServer`
- **Port:** 445/TCP
- **Configuration surfaces:**
  - `Get-SmbServerConfiguration → RequireSecuritySignature, EnableSecuritySignature`
  - Registry: `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature`

## Vulnerable Configuration
```powershell
PS> Get-SmbServerConfiguration | Select RequireSecuritySignature,EnableSecuritySignature
RequireSecuritySignature EnableSecuritySignature
------------------------ -----------------------
                   False                   False
```

## Remediation Steps
1. Require SMB signing on the server:
   ```powershell
   Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
   ```
2. Require SMB signing on the client side as defense-in-depth for any outbound mounts:
   ```powershell
   Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
   ```
3. Pair with LLMNR / NBT-NS disablement (see scenario-13) and, where the domain allows
   it, Extended Protection for Authentication (EPA) on LDAP and ADCS to close the
   remaining relay paths.
4. Verify that SMBv2/3 clients can still read/write a share — signing is transparent to
   them, only legacy SMBv1-only clients will break.
