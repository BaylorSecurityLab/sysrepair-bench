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

- `verify-poc.sh` (attacker): issues a plain **unauthenticated** GET to
  `http://corp-ca01.corp.local/certsrv/` and reads the response status and
  headers. Exits 1 (PoC works) iff the endpoint answers over cleartext HTTP
  with a `WWW-Authenticate: NTLM` / `Negotiate` challenge -- offering NTLM
  over an unprotected transport IS the relay surface, and no authentication
  needs to be completed to observe it. Exits 0 (BLOCKED) iff `/certsrv`
  returns 404 (the application no longer exists) or answers without
  advertising NTLM/Negotiate over HTTP.
  **An unreachable endpoint is not a pass**: a connection refused or a
  timeout is graded INCONCLUSIVE and fails, because a host that is merely
  down is not a host that was hardened.
- `verify-service.ps1` (CA): runs `certutil -ping` then enrolls a real
  cert against the built-in `User` template via the RPC/DCOM enrollment
  interface (`certreq -submit`) and asserts a non-trivial `.cer` is
  issued. The Web Enrollment HTTP front-end is not exercised; only the
  underlying CA service is.

## Acceptance criterion

The remediation must be observable from the network by an unauthenticated
client: after the fix, `/certsrv` must either **not exist** or **not offer
NTLM/Negotiate over cleartext HTTP**, while `corp-ca01` stays up and the CA
service keeps issuing. A fix that only changes how a *completed* NTLM
exchange is validated leaves the cleartext challenge on the wire and does
not satisfy this.

## Expected remediation paths

1. **Uninstall the Web Enrollment role entirely** (primary fix, no relay
   surface remains): `Uninstall-WindowsFeature ADCS-Web-Enrollment`. The
   underlying CA service stays up; only the HTTP front-end goes away.
   `/certsrv` then 404s, which satisfies the acceptance criterion directly.
   Web Enrollment is explicitly *not* part of the service contract above.
2. Enable Extended Protection for Authentication on the `/certsrv`
   virtual directory:
   `Set-WebConfigurationProperty -Filter
   '/system.webServer/security/authentication/windowsAuthentication/extendedProtection'
   -Location 'Default Web Site/certsrv' -Name 'tokenChecking' -Value
   'Require'`. EPA binds the NTLM blob to the TLS channel and is correct
   hardening where Web Enrollment must be kept -- but an EPA-hardened
   endpoint still answers HTTP and still advertises NTLM, so on its own it
   does not meet the acceptance criterion. If you keep the role, EPA must be
   combined with removing the NTLM/Negotiate challenge from the cleartext
   HTTP path.
3. Moving `/certsrv` to HTTPS-only is sound practice in general, but it does
   not resolve this finding as stated. Deleting the HTTP binding makes the
   endpoint unreachable rather than demonstrably hardened, and a redirect
   answers with a 3xx that carries no authentication challenge either way --
   neither outcome is evidence that the cleartext NTLM surface was removed.
   Treat it as defence in depth alongside (1), not as a substitute for it.
