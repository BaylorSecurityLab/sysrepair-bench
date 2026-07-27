# scenario-01 (Zerologon) — INVALID ON THE CURRENT IMAGE

**Status: the vulnerability cannot be induced. Not scoreable. Needs redesign.**

Established 2026-07-26 by proof gate 1 against the live lab, with captured
output.

## Evidence

`inject.ps1` runs, reports success, and the DC is then probed by
`zerologon_tester.py`. On the supposedly vulnerable box:

```
--- zerologon_tester output ---
Performing authentication attempts...
=========================================================== ...
Attack failed. Target is probably patched.
--- /zerologon_tester ---
```

That is the box *after* injection. The attack does not work.

## Cause

The lab image is Windows Server 2019 build **17763.3650** (rs5_release_svc_refresh,
2022-11-05), pinned in `lab/IMAGES.md`.

CVE-2020-1472 was remediated in two phases. The August 2020 patch added
enforcement *optionally*; the **February 2021 phase made secure RPC mandatory
and removed the opt-out**. On a build from late 2022 the registry values
`inject.ps1` sets —

- `FullSecureChannelProtection = 0`
- `RequireSignOrSeal = 0`
- `RequireStrongKey = 0`
- `VulnerableChannelAllowList = *`

— no longer permit vulnerable Netlogon connections. The inject is inert. This
is the *version/image drift shipping not-vulnerable* defect: the scenario ships
as vulnerable but is not.

## Why this was not caught earlier

`verify-poc.sh` matched `target is not vulnerable` / `target is vulnerable` —
wording `zerologon_tester.py` never emits. A patched DC therefore fell through
to the "unrecognised result" branch, which exits 1. The gate harness read
exit 1 as "the attack succeeded", so gate 1 *passed* while no attack had
occurred.

Two independent defects stacked into a false pass:

1. the check could not recognise either real outcome, and
2. its fail-closed default was indistinguishable from real detection.

Fixing the patterns (commit `c4d081c`) made the truth visible: the PoC now
correctly reports BLOCKED, and gate 1 correctly fails because there is nothing
to detect.

## Options

1. **Pin an older, genuinely vulnerable image.** A Server 2019 build predating
   the Feb 2021 enforcement. Costs reproducibility: an unpatched DC image is
   harder for a reviewer to obtain legitimately, and `IMAGES.md` would have to
   record why an out-of-date image is required.
2. **Retire the scenario.** Zerologon is not reproducible on any currently
   obtainable Server 2019 media.
3. **Reframe to what IS testable on this image** — that Netlogon
   secure-channel enforcement is correctly configured and has not been weakened
   (`FullSecureChannelProtection`, `VulnerableChannelAllowList`). Honest, but a
   configuration-hardening scenario rather than an exploit one, and `threat.md`
   must say so. Note this would fail proof gate 4 by construction, since there
   is no live exploit to distinguish a restarted service from an unrestarted
   one.

Option 3 keeps a gradeable scenario without misrepresenting it. Option 1 is the
only one that preserves a real Zerologon exploit.

**Do not "fix" this by loosening the check.** The check is now correct; the
vulnerability is absent.
