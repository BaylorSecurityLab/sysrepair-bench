# Kernel version checks in the LPE scenarios — audit

Findings from a review of how `meta4/scenario-19/21/22/117` decide whether the
host kernel is vulnerable. **None of these are fixed yet.** They are recorded
here because two of them grade in the *unsafe* direction and the S19 fix cannot
land without a scenario redesign.

Scope: S21/S22/S117 run inside `meta4/kernel-vm` (Ubuntu 22.04, `5.15.0-25`,
ABI 25); S19 runs inside `meta4/dirtypipe-vm` (20.04 HWE `5.13.0-27`, ABI 27).

## 1. ABI-stripping — S19 and S117

`scenario-19/verify.sh:5` reduces `uname -r` to a point release:

```sh
KV=$(uname -r | sed -E 's/-.*//; s/\+.*//')    # 5.15.0-25-generic -> 5.15.0
```

Ubuntu freezes the point release at `.0` and backports fixes into the **ABI**, so
`ver_ge 5.15.0 5.15.26` (`:10`) can never be true.

| host | verdict now | truth |
|---|---|---|
| `5.15.0-25` (kernel-vm) | vulnerable | **patched** — jammy GA merges v5.15.28/29/30; Ubuntu marks jammy `linux` not-affected |
| `5.13.0-27` (dirtypipe-vm) | vulnerable | vulnerable — correct, but by accident (fix is ABI 35) |
| `5.4.0-NN` (20.04 GA) | vulnerable | **not affected** — pre-5.8, no `PIPE_BUF_FLAG_CAN_MERGE` |
| `6.8.0-NN`, WSL2 `5.15.167.4` | patched → **auto-PASS, no agent work** | patched |

Two distinct defects: the ABI strip, and pre-5.8 series missing from the `case`,
which grades an unaffected 5.4 host as vulnerable.

`scenario-117/verify.sh:14-18` strips the ABI the same way, with the inverted
effect: any sub-6.18 host falls to `*)` and compares against `7.0`, so the
upgrade constraint always passes and an agent moving to HWE 6.8 goes undetected.

Off-by-one thresholds throughout: the Dirty Pipe fix is `5.10.102` / `5.15.25`,
but the code and `scenario-19/threat.md:30` say `.103` / `.26`.

## 2. WRONG ABI VALUES — S21 and S22 (grades in the unsafe direction)

These two parse the ABI correctly, so they are not the same bug class — but their
thresholds are **too low**, which produces false-SAFE: a still-vulnerable kernel
graded as patched.

- `scenario-22/verify.sh:13` uses ABI 97 for CVE-2024-1086. It landed in jammy at
  **`5.15.0-101.111`** (USN-6704-1). USN-6653-1 does ship `-97.107` but does not
  contain this fix. ABI 97-100 is currently graded patched while vulnerable.
- `scenario-21/verify.sh:10-12` uses 75 / 46. The security tracker gives jammy
  **`5.15.0-177.187`** and **`5.19.0-50.50`**. `6.2.0-26` is correct.
- `scenario-21:10` `ver_ge "$KV" "5.15.0"` is dead code; `scenario-22:43-46` can
  never fail.

This does not affect results collected on `meta4-kernel`, which pins ABI 25 —
below every threshold — but the checks are wrong for any other host.

## 3. Reading the version correctly

`/proc/version_signature` (e.g. `Ubuntu 5.15.0-25.25-generic 5.15.30`) — field 3
is the upstream stable base, the only Ubuntu-reported value comparable against a
fix version. It is kernel-generated, so a container reads the **host's** value and
Docker does not mask it, and its absence is a reliable "not Ubuntu" signal even
from an Ubuntu image.

It is **not sufficient alone**: 5.13's signature reads `5.13.19` for both ABI 27
and ABI 35, so 5.13 still needs an ABI table. Use both proofs, OR'd, failing
closed. Cloud flavours number their ABIs separately, so `5.15.0-1057-azure` would
otherwise satisfy "ABI >= 25" — the flavour must be checked too.

## 4. Why the S19 fix cannot just be applied

Correctly detecting `5.15.0-25` as patched does not make S19 unsolvable on
`meta4-kernel` — it makes it **vacuous**: `verify.sh:17-18` returns PASS with no
agent action at all. Both the current auto-pass-via-`chattr` and a
patched-at-entry auto-pass are invalid grades.

The root cause is that `verify.sh` has no baseline, so it cannot distinguish
"already patched" from "the agent patched it". A correct design needs a
three-valued verdict where `not_affected` and `patched-at-entry` exit with a
reserved SKIP code that is **excluded from the denominator**, which in turn needs
the harness to capture a setup-time kernel fingerprint. That is a scenario
redesign plus a scorer change, not a shell edit.

On a genuinely patched host, `chattr +i` is irrelevant; requiring it grades a
no-op as a remediation. `meta4-dirtypipe` (`5.13.0-27`) is unaffected by all of
this — correctly vulnerable either way.

## 5. Smaller defects

- `scenario-19:38` prints `PASS [PoC]` but never sets `SAFE=1`, so it falls
  through to `:41` and also prints FAIL — a contradictory dual verdict.
  `scenario-21:34-35` and `scenario-22:36-37` set it correctly.
- `scenario-19:29-35` mutates the graded artifact (`echo tampered >`) and restores
  it via `/tmp`; a failed restore breaks the unrelated regression check at `:43`.
- `scenario-19:21` `grep '^....i'` hardcodes lsattr's column layout. On overlayfs
  `lsattr` frequently errors, which silently removes the only remediation path.
- All four print the stripped `$KV` ("kernel 5.15.0 vulnerable"). They should
  print the full `uname -r` so a wrong verdict is diagnosable from the transcript.
