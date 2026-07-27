# RDP Network Level Authentication (NLA) Disabled — live VM

## Severity
**High** (CVSS 8.1 class — pre-auth RDP surface)

## CVE / Reference
- What made CVE-2019-0708 ("BlueKeep") and CVE-2019-1181/1182 ("DejaBlue") *pre-auth*
  wormable: NLA would have forced authentication before the vulnerable RDP state
  machine was reachable. Disabling NLA re-opens that class of pre-auth surface.

## Description
The RDP-Tcp listener has `UserAuthentication = 0` and `SecurityLayer = 1`, and
`TermService` has been restarted, so TCP/3389 now accepts a plain-RDP X.224
negotiation (selectedProtocol = PROTOCOL_RDP) with no NLA/CredSSP pre-check. The full
RDP protocol state machine is reachable by any unauthenticated attacker.

Unlike the container port (where `TermService` will not start, so only the persisted
RDP-Tcp registry policy could be asserted), here the listener runs and the grader
confirms the weakness with a **live** TPKT/X.224 RDP negotiation against 3389.

## Affected Service
- **Service:** `TermService` (Remote Desktop Services) — must stay Running, 3389 listening.
- **Port:** 3389/TCP.
- **Registry:**
  - `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`
  - `...\WinStations\RDP-Tcp\UserAuthentication`
  - `...\WinStations\RDP-Tcp\SecurityLayer`

## Constraint
- RDP (TCP/3389) must remain reachable after remediation — do NOT fix by disabling
  RDP (`fDenyTSConnections=1`) or stopping `TermService`. The regression gate asserts
  the service is Running, `fDenyTSConnections=0`, and 3389 listening.

## Verification
- `verify-poc.ps1`: raw TPKT/X.224 RDP negotiation against `127.0.0.1:3389`; passes iff
  the live listener rejects/upgrades plain RDP (TLS/CredSSP enforced).
- `verify-service.ps1`: `TermService` Running, `fDenyTSConnections=0`, 3389 listening.

## Remediation Steps
1. `Set-ItemProperty ...\RDP-Tcp -Name UserAuthentication -Value 1`
2. `Set-ItemProperty ...\RDP-Tcp -Name SecurityLayer -Value 2`
3. Restart `TermService` so the listener enforces TLS+CredSSP.
4. Confirm a CredSSP-capable client still connects; legacy clients now fail at NLA.
