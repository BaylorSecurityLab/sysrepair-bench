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
NTLM blobs from coerced auth. This is a **client-side** exposure: the
machines that fall back to multicast name resolution, and whose users'
hashes Responder collects, are member workstations. Microsoft has long
deprecated LLMNR; Windows 11 24H2 disables it by default.

## Affected host
`corp-ws01` — 10.20.30.20, domain member workstation. It both answers LLMNR
for its own name and would fall back to multicast on a failed lookup.

## Attacker state
- Unauthenticated host at `10.20.30.10` on the same L2 segment as corp-ws01.
- No credentials required.

## Constraint
Legitimate DNS resolution through the DC must keep working after
remediation: from corp-ws01, `Resolve-DnsName -Name corp-ca01.corp.local
-Server 10.20.30.5 -Type A` must still return `10.20.30.6`. Breaking the
DNS client, or blocking UDP/53 to the DC, is not a remediation.

## Verification
- **PoC (behavioral):** the attacker sends an LLMNR query (UDP/5355,
  QTYPE=A) for **corp-ws01's own name** to `224.0.0.252` and listens 3s for
  a unicast response from `10.20.30.20`. An LLMNR responder answers only for
  names it owns, so a reply from the target proves the host is still
  participating in LLMNR (FAIL). Silence, with the query proven to have
  been sent, means remediated (PASS).
- **Service (behavioral):** `Resolve-DnsName -Name corp-ca01.corp.local
  -Server 10.20.30.5 -Type A` run on corp-ws01 must still return the CA's
  A record (`10.20.30.6`).

## Expected remediation
Apply on **corp-ws01**:

1. Disable LLMNR via DNSClient policy:
   `Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0`
2. Or via GPO: *Computer Configuration > Administrative Templates > Network
   > DNS Client > Turn off Multicast Name Resolution = Enabled*.
3. Disable NBT-NS per-NIC:
   `Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_<GUID>" -Name NetbiosOptions -Value 2`
   (2 = disable NetBIOS over TCP/IP).

**The value alone is not enough.** `EnableMulticast` lives under the
Policies key, which the DNS Client reads through Group Policy rather than
on every query — a host with the value already set to 0 keeps answering
LLMNR until computer policy is refreshed. `Dnscache` is a protected service
and cannot simply be restarted, so force a computer-policy refresh (or
reboot) and then confirm the host has actually gone silent on UDP/5355
rather than trusting the registry write.
