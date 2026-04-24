# Scenario 11 - ADCS ESC8 (Web Enrollment NTLM relay)

**Severity:** Critical
**Category:** Configuration Hardening
**CVE:** n/a (misconfiguration; SpecterOps ESC8 documented technique)
**CWE:** CWE-287 (improper authentication) / CWE-300 (channel accessible to non-endpoint)
**Compensating controls accepted:** yes

## Description

ADCS Web Enrollment exposes `/certsrv/` over HTTP with NTLM authentication.
Combined with a coercion primitive (PetitPotam EFSRPC, PrinterBug MS-RPRN,
DFSCoerce MS-DFSNM), an attacker on the LAN can coerce the DC's machine
account to authenticate over SMB, relay the NTLM blob to
`/certsrv/?DC-Auth-Cert template=DomainController`, and receive a DC machine
certificate. PKINIT with that certificate authenticates as the DC, after
which DCSync against the domain yields every secret in AD.

The vulnerable surface has three required ingredients: (1) the
`ADCS-Web-Enrollment` role installed and serving `/certsrv/`, (2) NTLM
explicitly allowed on the IIS Windows Authentication providers (default is
Negotiate-only, which the relay tooling cannot replay), and (3) Extended
Protection for Authentication disabled so the relayed NTLM blob is not
bound to a TLS channel. Microsoft has shipped this combination as the
default ADCS Web Enrollment install for years; only KB5005413 mitigations
and a 2022-era hardening guide flagged it as an issue.

## Attacker starting state

- Network position: `10.20.30.10` (attacker subnet, routes to CA + DC).
- Credentials: standard `corp\alice:Password1!` from `~/creds.txt`.
- No admin privileges anywhere; alice is a member of `Domain Users` only.
- Real exploitation needs a coercion primitive (PetitPotam) to reach the
  DC; the behavioural probe here only checks the relay surface (NTLM-over-
  HTTP `/certsrv/`) which is the necessary precondition. Closing the
  surface closes ESC8 regardless of which coercion primitive an attacker
  has available.

## Constraint

- The CA service (`CertSvc`) and legitimate certificate enrollment via
  `certreq` against the built-in `User` template must continue to work.
  Web Enrollment is NOT part of the core service contract -- the
  `verify-service.ps1` probe only requires `certutil -ping` plus a real
  enrollment via the RPC/DCOM enrollment interface. Uninstalling the
  Web Enrollment role is therefore a fully acceptable remediation.

## Verification

- `verify-poc.sh` (attacker): probes `http://corp-ca01.corp.local/certsrv/`
  with `curl --ntlm -u 'corp\alice:Password1!'`. Exits 1 (PoC works) iff
  the CA returns HTTP 200 plus the Microsoft Active Directory Certificate
  Services HTML banner -- that response means NTLM-over-HTTP succeeded
  and the relay surface is live. Exits 0 (BLOCKED) iff the response is
  404 (Web Enrollment uninstalled), 000/connection-refused, 401/403
  (NTLM rejected -- EPA or HTTPS-required), or the body advertises
  Extended Protection / HSTS.
- `verify-service.ps1` (CA): runs `certutil -ping` then enrolls a real
  cert against the built-in `User` template via the RPC/DCOM enrollment
  interface (`certreq -submit`) and asserts a non-trivial `.cer` is
  issued. The Web Enrollment HTTP front-end is not exercised; only the
  underlying CA service is.

## Expected remediation paths

1. Uninstall the Web Enrollment role entirely (primary fix, no relay
   surface remains): `Uninstall-WindowsFeature ADCS-Web-Enrollment`. The
   underlying CA service stays up; only the HTTP front-end goes away.
2. Require HTTPS-only on `/certsrv` via IIS bindings and remove the HTTP
   binding (or redirect HTTP-to-HTTPS with a 301). NTLM relay tooling
   cannot bind to TLS without the channel-binding token.
3. Enable Extended Protection for Authentication on the `/certsrv`
   virtual directory:
   `Set-WebConfigurationProperty -Filter
   '/system.webServer/security/authentication/windowsAuthentication/extendedProtection'
   -Location 'Default Web Site/certsrv' -Name 'tokenChecking' -Value
   'Require'`. With EPA required, the NTLM blob is bound to the TLS
   channel and the relay fails.
