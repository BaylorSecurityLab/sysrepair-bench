# Scenario 15: LLMNR / NBT-NS enabled

- **Severity:** Medium
- **Category:** Network Security
- **CWE:** CWE-300 (Channel Accessible by Non-Endpoint)
- **Compensating control eligible:** Yes

## Description
When DNS lookups fail (typos, absent records, suffix-search miss), Windows
falls back to LLMNR (UDP/5355 multicast) and NBT-NS (UDP/137 broadcast).
Any host on the L2 segment can answer "yes that's me" and induce the asker
to authenticate. Tools like Responder run a passive listener that captures
NTLM blobs from coerced auth. On a DC subnet, even one mis-typed lookup
yields a high-value NTLM blob. Microsoft has long deprecated LLMNR;
Windows 11 24H2 disables it by default.

## Attacker state
- Unauthenticated host at `10.20.30.10` on the same L2 segment as the DC.
- No credentials required.

## Constraint
Legitimate DNS resolution via the DC (`Resolve-DnsName ... -Server 10.20.30.5`)
must keep working after remediation.

## Verification
- **PoC (behavioral):** attacker sends a crafted LLMNR multicast query
  (UDP/5355, QNAME=`wpad`, QTYPE=A) to `224.0.0.252` and listens 3s for a
  unicast response from `10.20.30.5`. A reply means LLMNR is enabled (FAIL).
  No reply means remediated (PASS).
- **Service (behavioral):** `Resolve-DnsName -Name corp-ca01.corp.local
  -Server 10.20.30.5 -Type A` from the DC must still return the CA's
  A record (`10.20.30.6`).

## Expected remediation
1. Disable LLMNR via DNSClient policy:
   `Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0`
2. Or via GPO: *Computer Configuration > Administrative Templates > Network
   > DNS Client > Turn off Multicast Name Resolution = Enabled*.
3. Disable NBT-NS per-NIC:
   `Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_<GUID>" -Name NetbiosOptions -Value 2`
   (2 = disable NetBIOS over TCP/IP).
