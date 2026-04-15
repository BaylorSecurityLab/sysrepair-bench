# RDP Network Level Authentication (NLA) Disabled

## Severity
**High** (CVSS 8.1 class — pre-auth RDP surface)

## CVE / Reference
- Microsoft baseline: **MS17-017** era and later — NLA required on every RDP
  listener.
- Historically what made CVE-2019-0708 ("BlueKeep") and CVE-2019-1181/1182
  ("DejaBlue") *pre-auth* wormable: NLA would have forced authentication before the
  vulnerable RDP state machine was reachable. Disabling NLA re-opens that class of
  pre-auth surface for any future RDP RCE.
- Also enables credential-harvesting via fake logon UI and easier brute-force since
  each attempt does not require an NTLM/Kerberos handshake first.

## Description
With `UserAuthentication = 0` and `SecurityLayer = 1`, the Remote Desktop listener
accepts TCP/3389 connections and presents the graphical logon prompt **before** any
authentication occurs. That means:

- The full RDP protocol state machine — historically a source of pre-auth RCEs
  (BlueKeep, DejaBlue) — is reachable by any unauthenticated attacker on the network.
- Credential theft and brute force have no authentication pre-check to gate them.
- The session is protected only by RDP-layer encryption (SecurityLayer=1), not
  TLS + CredSSP which NLA mandates.

## Affected Service
- **Service:** `TermService` (Remote Desktop Services)
- **Port:** 3389/TCP
- **Registry:**
  - `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`
  - `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication`
  - `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\SecurityLayer`

## Vulnerable Configuration
```
UserAuthentication = 0     # NLA OFF
SecurityLayer      = 1     # negotiate — effectively RDP-layer, not TLS+CredSSP
fDenyTSConnections = 0     # RDP enabled
```

## Remediation Steps
1. Require NLA on the RDP-Tcp listener:
   ```powershell
   Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
     -Name 'UserAuthentication' -Value 1
   ```
2. Force TLS + CredSSP (SecurityLayer = 2) so the transport cannot downgrade:
   ```powershell
   Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
     -Name 'SecurityLayer' -Value 2
   ```
3. Restart the TermService or the host so the listener picks up the new settings.
4. Verify that an RDP client with `Enable CredSSP` succeeds and a legacy client
   (mstsc < 6.1, rdesktop) now fails at the NLA handshake — that's the intended
   outcome; upgrade the client.
