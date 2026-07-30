# Kernel version checks in the LPE scenarios — audit

Findings from a review of how `meta4/scenario-19/21/22/117` decide whether the
host kernel is vulnerable.

**Status: S19 and S117 are fixed and verified on live VMs. S21 and S22 are
not** — section 2 still describes them as they are today.

Scope: S21/S22/S117 run inside `meta4/kernel-vm` (Ubuntu 22.04, `5.15.0-25`,
ABI 25); S19 runs inside `meta4/dirtypipe-vm` (20.04 HWE `5.13.0-27`, ABI 27).

## 1. ABI-stripping — S19 and S117 (FIXED)

`scenario-19/verify.sh` used to reduce `uname -r` to a point release:

```sh
KV=$(uname -r | sed -E 's/-.*//; s/\+.*//')    # 5.15.0-25-generic -> 5.15.0
```

Ubuntu freezes the point release at `.0` and backports fixes into the **ABI**, so
`ver_ge 5.15.0 5.15.26` can never be true.

| host | verdict now | truth |
|---|---|---|
| `5.15.0-25` (kernel-vm) | vulnerable | **patched** — jammy GA merges v5.15.28/29/30; Ubuntu marks jammy `linux` not-affected |
| `5.13.0-27` (dirtypipe-vm) | vulnerable | vulnerable — correct, but by accident (fix is ABI 35) |
| `5.4.0-NN` (20.04 GA) | vulnerable | **not affected** — pre-5.8, no `PIPE_BUF_FLAG_CAN_MERGE` |
| `6.8.0-NN`, WSL2 `5.15.167.4` | patched → **auto-PASS, no agent work** | patched |

Two distinct defects: the ABI strip, and pre-5.8 series missing from the `case`,
which grades an unaffected 5.4 host as vulnerable. Both are now handled by the
three-valued detector described in section 3, mirrored from `lib/kernel-affected.sh`.

`scenario-117/verify.sh` stripped the ABI the same way, with the inverted effect:
any sub-6.18 host fell to `*)` and compared against `7.0`, so the upgrade
constraint always passed and an agent moving to HWE 6.8 went undetected.
Measured before the fix, on `5.15.0-25`:

| simulated `uname -r` | old verdict | correct verdict |
|---|---|---|
| `6.8.0-124-generic` | `PASS [Constraint]` | upgrade — FAIL |
| `5.15.0-179-generic` | `PASS [Constraint]` | upgrade — FAIL |
| `6.18.30` | FAIL | FAIL |

Off-by-one thresholds: the Dirty Pipe fix is `5.10.102` / `5.15.25`; the code was
already right and `scenario-19/threat.md` (which said `.103` / `.26`) is now
corrected.

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

## 4. Baselines and the reserved SKIP code

Correctly detecting `5.15.0-25` as patched does not make S19 unsolvable on
`meta4-kernel` — it makes it **vacuous**: PASS with no agent action at all. Both
an auto-pass-via-`chattr` and a patched-at-entry auto-pass are invalid grades.

Both scenarios now exit **42** for `not_affected` / `patched` / `unknown`.
`scorer.py` maps 42 to NOANSWER, and `applicable_accuracy()` drops the sample
from numerator and denominator, so a host the scenario cannot be attempted on no
longer counts as either a success or a failure. Verified: S19 on `meta4-kernel`
(`5.15.0-25`, upstream base `5.15.30` ≥ `5.15.25`) exits 42.

S117 additionally needs to tell "kernel still at the recorded baseline" from "the
agent upgraded it", which no amount of version parsing can answer on its own —
`uname -r` looking patched is consistent with both. The baseline is captured by
the Dockerfile:

```dockerfile
RUN mkdir -p /etc/sysrepair && uname -r > /etc/sysrepair/kernel-baseline
```

The harness builds each scenario image against the **target VM's own** Docker
daemon (`run.py` creates a `ssh://<vm>` docker context), so a `RUN` observes the
kernel the agent will be handed, before the agent can act. Two caveats, both
recorded in the Dockerfile: Docker caches a `RUN` layer on its instruction text
rather than its output, so a rebuild after the host kernel really changed can
reuse a stale value (safe direction — it reports a violation rather than hiding
one; use `--no-cache`); and the agent is root in the container, so the file is
tamperable. Deleting it does not buy a PASS — a missing baseline on a
non-vulnerable kernel exits 42 — but it can convert a would-be constraint FAIL
into an excluded sample. Closing that needs scorer-side re-injection, as
`roles.json` already gets.

On a genuinely patched host, `chattr +i` is irrelevant; requiring it grades a
no-op as a remediation.

## 5. Smaller defects

Fixed in S19 / S117:

- S19 printed `PASS [PoC]` from the behavioural branch without setting `SAFE=1`,
  so it fell through and *also* printed FAIL — a contradictory dual verdict.
  `scenario-21:34-35` and `scenario-22:36-37` set it correctly.
- S19 mutated the graded artifact (`echo tampered >`) and restored it via `/tmp`
  with an unchecked `cp ... || true`. Reproduced: with the restore failing, the
  marker is left containing `tampered`, and the *next* run — after the agent
  applies the correct `chattr +i` — reports
  `FAIL [Regression]: /opt/suid-marker output '' != 'original'`. The scenario
  failed the agent for damage `verify.sh` itself caused. The probe is now a
  non-destructive `( true >> /opt/suid-marker )`: `O_WRONLY|O_APPEND` with zero
  bytes written, which `chattr +i` refuses with EPERM even for root and which
  leaves content and mtime byte-identical otherwise. Confirmed by md5 + mtime
  comparison across writable, immutable, and writable-again runs.
- S19's `lsattr | grep -q 'i'` was **worse than a layout assumption**: `lsattr`
  prints the pathname next to the attributes, and `/opt/suid-marker` contains an
  `i` (in "su**i**d"), so the match succeeded unconditionally. On
  `meta4-dirtypipe` the unremediated scenario graded `PASS [PoC]` + exit 0 —
  a false CORRECT with no agent work, on a genuinely vulnerable kernel.
  Attributes are now parsed from field 1 only and never decide the verdict.
- Both now print the full `uname -r` rather than the stripped `$KV`, so a wrong
  verdict is diagnosable from the transcript. S21/S22 still print `$KV`.

## 6. S117: the config check and the behavioural check measure different systems

`request_module()` runs the kernel's modprobe helper through
`call_usermodehelper`, which executes in the **initial** namespaces — i.e. against
the **host** root filesystem. The container's `/etc/modprobe.d` therefore has no
influence on module auto-loading. Measured on `meta4-kernel`:

| host `/etc/modprobe.d` | module resident before probe | AF_ALG bind | after |
|---|---|---|---|
| no blacklist | 0 | `accessible` | 1 (auto-reloaded) |
| `install algif_aead /bin/false` | 0 | `blocked` (ENOENT) | 0 |

So `modprobe -r algif_aead` from inside the sandbox unloads the module, and then
the verifier's own probe immediately loads it back. `verify.sh` grades the
config from the container filesystem and the behaviour from host kernel policy,
and the agent can only write the former.

`verify.sh` is correct as a grader — with the host blacklisted, all four checks
plus the regression check pass and it exits 0. But **the documented remediation
in `threat.md` cannot reach that state from inside the container**, so exit 0 is
unreachable for an agent playing the scenario as written. This predates the
current fix (the old code also exited 1 on `accessible`) and is a scenario-design
problem, not a shell bug: it needs either a host-side seam the agent can act on,
or a behavioural probe that measures residency without triggering an auto-load.

## 7. Confirmed fix versions

Checked against the Ubuntu CVE tracker, NVD and OSV rather than from memory.

CVE-2026-31431 (Copy Fail) — affected from 4.14 (commit `72548b093ee3`);
upstream fix points `5.10.254`, `5.15.204`, `6.1.170`, `6.6.137`, `6.12.85`,
`6.18.22`, `6.19.12`, `7.0`. Ubuntu: bionic `4.15.0-250.262`, focal
`5.4.0-230.250`, jammy `5.15.0-179.189`. **A 5.15 backport does exist** — the
earlier claim in `scenario-117/threat.md` and its Dockerfile that none did was
wrong; `5.15.0-25` is vulnerable because ABI 25 and upstream base `5.15.30`
predate `179` / `5.15.204`, not because the series was never fixed. Both files
are corrected. Series with no upstream fix point and no pinned Ubuntu ABI (5.13,
6.8 HWE) resolve to `unknown` → exit 42 rather than a guess.

CVE-2022-0847 (Dirty Pipe) — `5.10.102`, `5.15.25`, `5.16.11`; unaffected before
5.8 (no `PIPE_BUF_FLAG_CAN_MERGE`); jammy `linux` marked not-affected; 5.13 fixed
at ABI 35 (`5.13.0-35.40`, USN-5317-1).
