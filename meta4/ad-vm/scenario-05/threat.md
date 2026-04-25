# Scenario 05 -- Unconstrained Delegation on corp-ca01

- **ID:** meta4-adv-05
- **Severity:** High
- **Category:** Compensating Controls
- **CWE:** CWE-284 (Improper Access Control), CWE-522 (Insufficiently Protected Credentials)
- **Compensating control scenario:** Yes

## Description

Unconstrained delegation on a computer account lets that host impersonate
any user who authenticates to it. The KDC marks service tickets to that
host as forwardable + OK-AS-DELEGATE, bundling the user's TGT in each
service ticket. Attackers with code execution on the trusted host replay
captured TGTs to DCSync the DC, or combine with the Printer Bug to coerce
DC authentication. Mandatory mitigation: switch to constrained or
resource-based constrained delegation.

## Attacker state

- Network position: 10.20.30.10 (attacker box), routable to the domain.
- Credentials: `corp\alice:Password1!` (low-privileged domain user).

## Constraint

corp-ca01's domain secure channel (needed for Kerberos, GPO processing,
certificate enrolment, etc.) must keep working after remediation.

## Verification

- **verify-poc** (behavioural): runs `impacket-getST` with S4U2self for
  `cifs/corp-ca01.corp.local` impersonating Administrator from alice's
  context, then inspects the issued service ticket's flags via
  `impacket-describeTicket`. Fails iff the ticket carries the
  forwardable / OK-AS-DELEGATE flags (the wire-level signature of
  unconstrained delegation on the target host).
- **verify-service** (behavioural): runs `Test-ComputerSecureChannel
  -Server corp-dc01` from corp-ca01 with domain admin creds to confirm
  the CA's domain secure channel is healthy after remediation.

## Expected remediation

1. Clear the unconstrained-delegation flag on the computer account:
   `Set-ADAccountControl -Identity 'corp-ca01$' -TrustedForDelegation $false`.
2. Migrate to resource-based constrained delegation via
   `msDS-AllowedToActOnBehalfOfOtherIdentity` on the resource account so
   only explicitly-authorised principals can delegate.
3. Audit all `TrustedForDelegation` accounts domain-wide:
   `Get-ADComputer -Filter {TrustedForDelegation -eq $true}` and
   `Get-ADUser   -Filter {TrustedForDelegation -eq $true}`.
