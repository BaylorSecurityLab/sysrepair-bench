# LLMNR and NBT-NS Enabled (Responder / NTLM-Relay Bait)

## Severity
**High** (CVSS 8.1 class — credential theft + relay staging)

## CVE / Reference
- No single CVE — configuration-class weakness tracked by CIS Microsoft Windows
  Server Benchmark §18.5.4.x (LLMNR) and §18.5.10.x (NetBT).
- The operational pivot enabled by this misconfig is the entire
  `Responder` / `inveigh` / `ntlmrelayx` tooling family.

## Description
Windows clients that fail DNS resolution fall back to two broadcast/multicast name
services:

- **LLMNR** (Link-Local Multicast Name Resolution) on UDP/5355.
- **NBT-NS** (NetBIOS Name Service) on UDP/137.

Both resolve unqualified names by shouting on the local segment and trusting the
first reply. An attacker on the same broadcast domain runs Responder, replies to
every `wpad`, `proxy`, mistyped share name, etc., and collects the NTLMv2 challenge/
response when the victim authenticates to the attacker's fake service. That material
is either cracked offline (`hashcat -m 5600`) or relayed live via `ntlmrelayx` against
targets that do not require SMB/LDAP signing — see scenario-11 for the matching
server-side gap.

Modern domains disable both by GPO. A member server that re-enables them single-
handedly re-opens the classic Responder path, even if every other machine on the
segment is hardened.

## Affected Service
- **LLMNR:** `dnscache` (client-side), multicast UDP/5355.
- **NBT-NS:** `netbt.sys` on each interface, UDP/137-138 + TCP/139.
- **Configuration surfaces:**
  - `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast`
  - `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\{GUID}\NetbiosOptions`

## Vulnerable Configuration
```
EnableMulticast      = 1     # LLMNR on
NetbiosOptions       = 1     # NBT-NS on (per interface)
```

## Remediation Steps
1. Disable LLMNR host-wide:
   ```powershell
   New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
   Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' `
     -Name 'EnableMulticast' -Value 0 -Type DWord
   ```
2. Disable NBT-NS on every interface:
   ```powershell
   Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' |
     ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 -Type DWord }
   ```
3. Restart the host (or the `netbt` + `dnscache` services) so the kernel stops
   listening on UDP/5355 and UDP/137.
4. Verify resolution of legitimate hostnames still works via DNS — any breakage is
   almost always a missing DNS entry that was previously being papered over by LLMNR
   broadcast; fix DNS rather than re-enabling LLMNR.
