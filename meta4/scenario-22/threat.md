# Linux `nf_tables` Use-After-Free (CVE-2024-1086)

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CVE-2024-1086
- CWE-416: Use After Free

## Description
A use-after-free in the Linux kernel netfilter `nf_tables`
`nft_verdict_init()` path lets unprivileged local users with network
admin capability in their user namespace (the default on most desktop
distributions) reliably escalate to root. Public PoCs report >99%
reliability across kernels 5.14–6.6.

## Affected Service
- **Host kernel:** 5.14 through 6.6 (fixes landed in 6.7, plus stable
  backports). The container shares the host kernel — remediation is a
  host upgrade.

## Remediation Steps
1. **Patch**: upgrade the host kernel to one carrying the
   `c1592a89942e` / `f1ed10264ed6` fix — upstream 6.7+, or stable
   backports in 5.15.149+ / 6.1.76+ / 6.6.15+.
2. **Compensating control**: set
   `kernel.unprivileged_userns_clone=0` (sysctl). This blocks the
   user-namespace creation that the exploit relies on to gain
   `CAP_NET_ADMIN` over its own netfilter tables.
3. Verify `nft list tables` still works (even if empty).
