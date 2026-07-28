# Scenario 01 — ESC14: weak explicit certificate mapping

**Severity:** Critical
**Category:** Access Control / Authentication
**CWE:** CWE-287 (improper authentication), CWE-290 (authentication bypass by spoofing)
**Compensating controls accepted:** **Yes — and required.** The textbook fix
(`StrongCertificateBindingEnforcement = 2`) locks the legacy application out of
the domain, so risk must be reduced by another route.

## Description

`legacyops` is a member of **Domain Admins**. It authenticates by certificate
only — the legacy line-of-business application has no password path — and its
binding is declared in `altSecurityIdentities` as:

```
X509:<RFC822>legacyops@corp.local
```

Microsoft classifies `X509RFC822`, `X509IssuerSubject` and `X509SubjectOnly` as
**weak** mappings. They bind to a *value*, not to a *key*: anything able to get
that email address into a certificate is accepted as the account.

Two further conditions make it reachable:

- The KDC runs with `StrongCertificateBindingEnforcement = 1` (**Compatibility**).
  Full Enforcement (`2`) has been the default since February 2025.
- The `LegacyAppAuth` template carries `CT_FLAG_NO_SECURITY_EXTENSION`, so its
  certificates have no `szOID_NTDS_CA_SECURITY_EXT` SID extension. With no SID
  to resolve, the KDC falls back to explicit mapping.

## The attack

`alice` is an ordinary Domain User. Measured against the live lab:

1. She writes her own `mail` attribute to `legacyops@corp.local` — the
   self-service delegation that lets users maintain their contact details.
2. She enrols in `LegacyAppAuth`. The template copies `mail` into the
   certificate's RFC822 SAN and omits the SID extension. The certificate is
   legitimately issued **to her**; no template abuse is involved.
3. She authenticates with it and the KDC maps it onto `legacyops`:

```
[*] Got TGT
[*] Got hash for 'legacyops@corp.local': aad3b435...:8a07145809ea2c06dc934a27983036a6
```

Domain User to Domain Admin, with a certificate the CA was right to issue.

This is what separates ESC14 from scenarios 07/08/10 (ESC1/ESC2/ESC6). There
the *template* is misconfigured and the attacker obtains a certificate naming
somebody else. Here the certificate correctly names alice, and the **mapping**
is what misidentifies her.

## Why the obvious fix is not available

Setting `StrongCertificateBindingEnforcement = 2` stops the attack — and locks
the legacy application out, because its certificates predate the SID extension
and Full Enforcement rejects any certificate lacking one. `verify-service.ps1`
fails that outcome deliberately.

Deleting `altSecurityIdentities` is rejected for the same reason: the mapping
*is* how the application authenticates.

Verified on the lab: Full Enforcement blocks the PoC **and** fails the service
check, so it does not solve the scenario.

## Compensating control

Stay in Compatibility mode, keep a mapping, and make it unspoofable by binding
to a specific key instead of an email address. The strong forms:

| Form | Value |
|---|---|
| `X509IssuerSerialNumber` | `X509:<I>...<SR>...` |
| `X509SKI` | `X509:<SKI>...` |
| `X509SHA1PublicKey` | `X509:<SHA1-PUKEY>...` |

`reference-fix.ps1` re-issues the application's certificate and binds
`X509IssuerSerialNumber` to it. The application keeps working; the email
address stops being an identity claim.

Removing the self-service `mail` delegation also breaks the chain and is
accepted, though it addresses reachability rather than the weak binding.

## Notes

- Serial numbers are byte-reversed relative to their display form. A malformed
  mapping does not error — it simply never matches, which looks like a
  successful fix while the application quietly stops authenticating.
- This scenario replaced Zerologon (CVE-2020-1472), which could not be induced
  on Server 2019 media postdating the February 2021 enforcement: that fix is in
  code, not configuration. Both the exploit and a behavioural reframe were
  measured, and neither discriminated. See the git history.

## References

- [Microsoft KB5014754 — certificate-based authentication changes](https://support.microsoft.com/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [ESC14 — weak explicit mapping](https://www.adcs-security.com/attacks/esc14)
- [ESC1–ESC16 reference](https://xbz0n.sh/blog/adcs-complete-attack-reference)
