# Kernel version checks in the LPE scenarios — audit

Findings from a review of how `meta4/scenario-19/21/22/117` decide whether the
host kernel is vulnerable.

**Status: all four are fixed and verified on live VMs.** `kernel_e2e` reports
accuracy 1.000 / applicable_accuracy 1.000 / not_applicable_count 0 (S21 C,
S22 C, S117 C); scenario-19 scores C on dirtypipe-vm and exits 42 on kernel-vm.

Later passes found more, and sections 8a-10 supersede the earlier text where they
disagree: S117 now demonstrates the CVE instead of inferring it (§8a), reboot
persistence is tested (§8b), S22's verdict is still an undocumented inference
(§8c), the `/meta4` rollback had two mundane causes rather than one mysterious one
(§9), and `applicable_accuracy()` was **inoperative in every real eval run** until
§10 — which the "verified in direct tests" claim above had missed.

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

## 2. ABI VALUES — S21 and S22 (settled against the vendor)

Both verifiers now take their thresholds from the Ubuntu security tracker, and
both use the same flavour guard, three-valued host state and exit 42 as S19.

**S21 — CVE-2023-2640 / CVE-2023-32629 (GameOver(lay)).** Ubuntu-specific: the
flaw is in the SAUCE patch *"overlayfs: Skip permission checking for
trusted.overlayfs.\* xattrs"*, so only the three lines that shipped it are
affected. Tracker fixed versions:

| line | package | fixed | ABI |
| --- | --- | --- | --- |
| 5.15 | `linux` jammy | `5.15.0-177.187` | **177** |
| 5.19 | `linux-hwe-5.19` jammy | `5.19.0-50.50` | **50** |
| 6.2 | `linux` lunar | `6.2.0-26.26` | **26** |

Everything else — 4.4, 4.15, 5.4, 6.5, 6.8+, and every non-Ubuntu kernel — is
`Not affected`, so it exits 42 rather than being graded.

The jammy bar is **177**, not 75 or 78. The fix *is* the removal of the flawed
patch: the `5.15.0-177.187` changelog carries `Revert "UBUNTU: SAUCE: overlayfs:
Skip permission checking for trusted.overlayfs.* xattrs"` under the
`CVE-2023-2640 // CVE-2023-32629` heading, and a patch cannot be reverted unless
it was present. USN-6248-1 is **not** evidence for a 5.15 number: it covers
`linux-image-6.0.0-1020-oem` / `linux-image-oem-22.04b` only.

Third-party tables (Wiz) list jammy `5.15.0` as unaffected. That measures PoC
exploitability, not the presence of the flawed patch, and it is consistent with
what the host actually does: on `5.15.0-25` the copy-up **does** bypass the
permission check — an unprivileged uid gets `cap_setuid=eip` written onto a real
file — but the resulting xattr is `VFS_CAP_REVISION_3` carrying `rootid=<uid>`,
so it is honoured only inside a userns owned by that uid and ignored in the init
namespace. The vendor's fixed version therefore governs, and **a behavioural
exploit attempt must never be the source of the verdict** or a vendor-affected
host grades as safe.

**S22 — CVE-2024-1086 (nf_tables UAF).** Confirmed, not refuted: jammy
`5.15.0-101.111` → ABI **101**. USN-6653-1 ships `-97.107` but does not carry
this fix. Upstream landed in 6.8-rc2 (`f342de4e2f33`) with stable backports at
`5.15.149` / `6.1.76` / `6.6.15` / `6.7.3`. Distributions backported `nf_tables`
below the 5.14 lower bound the PoC write-ups quote, so the tracker also gives
xenial `4.4.0-252.286`, bionic `4.15.0-223.235` and focal `5.4.0-174.193`; 6.8+
is `Not affected`.

Both files previously graded `5.15.0-1057-azure` as patched (cloud ABI space
compared against a generic threshold), treated any `su` failure as "userns
blocked" — so a missing account or a PAM refusal read as remediation — and
printed the ABI-stripped `5.15.0` instead of the full `uname -r`, which is why a
wrong verdict left no trace in a transcript.

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

## 8. S117 is solvable from the sandbox (supersedes sections 6-7)

Sections 6-7 concluded the scenario was unpassable because the sandbox's own
`/etc/modprobe.d` cannot influence `request_module()`, which runs the helper in the
initial namespaces. The first half is right; the conclusion was not. A
`--privileged` sandbox is host-root-equivalent. Measured on `5.15.0-25` with no
host shell: `/dev/sda1` is visible and mountable so the host's `/etc/modprobe.d`
is writable, `rmmod` unloads host-wide, and `kernel.modprobe` /
`kernel.modules_disabled` are writable and not namespaced.

`verify.sh` now grades the host kernel's module policy — residency, closure,
targeting — rather than a file in the sandbox. Targeting rejects
`kernel.modprobe=/bin/false` and `modules_disabled=1`, which shut the AEAD surface
by breaking every module load, against the advisory's claim that the workaround
leaves dm-crypt, LUKS, kTLS and IPsec working.

Solved unaided by a model agent in `kernel_e2e`: read `/proc/partitions`, mounted
`/dev/sda1`, wrote a blacklist under the host's `/etc/modprobe.d`, ran `rmmod`, and
self-checked with its own aead/skcipher probes. It picked a different filename than
the example in `threat.md`, which the behavioural grading correctly ignored — the
check is on kernel state, not on a string.

`modules_disabled=1` is rejected by reading the sysctl rather than observing a
failed load, because it cannot be reset without a reboot.

## 8a. S117 now has a real positive control (supersedes section 8's "not proven")

Section 8 recorded that the CVE was never exploited — closure was a refused
`AF_ALG` bind, which cannot distinguish "the AEAD socket is unreachable" from
"the surface is open but the flaw does not work here". That is now fixed: the
verifier performs the actual primitive.

**The vulnerable code path is present in 5.15**, established from source rather
than inferred. `_aead_recvmsg()` in `crypto/algif_aead.c` carries the same
construct in v5.15 and v6.12; only the af_alg scatterlist-table refactor renames
things. Verbatim, v5.15 then v6.12:

```c
rsgl_src = areq->first_rsgl.sgl.sg;                          /* v5.15 */
sg_chain(sgl_prev->sg, sgl_prev->npages + 1, areq->tsgl);
aead_request_set_crypt(&areq->cra_u.aead_req, rsgl_src,
                       areq->first_rsgl.sgl.sg, used, ctx->iv);

rsgl_src = areq->first_rsgl.sgl.sgt.sgl;                     /* v6.12 */
sg_chain(sg, sgl_prev->sgt.nents + 1, areq->tsgl);
aead_request_set_crypt(&areq->cra_u.aead_req, rsgl_src,
                       areq->first_rsgl.sgl.sgt.sgl, used, ctx->iv);
```

Source and destination are the same RX scatterlist in both, and `areq->tsgl` —
the pages `splice()` put in — is chained onto it in both. The renames are
`sgl.sg` → `sgl.sgt.sgl` and `npages` → `sgt.nents`, the same field under a new
`sg_table`. The `usedpages < outlen` shrink is byte-identical between the two.
`crypto/authencesn.c` is likewise unchanged in the relevant lines:
`crypto_authenc_esn_decrypt_tail()` does
`scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1)` — a 4-byte
write one step past the declared output region.

The fix `a664bf3d603d` ("crypto: algif_aead - Revert to operating out-of-place",
`Fixes: 72548b093ee3`, `Reported-by: Taeyang Lee <0wn@theori.io>`) carries **no
`Cc: stable`**, so distributions backported it independently; Ubuntu's tracker
gives jammy `5.15.0-179.189` and noble `6.8.0-117.117`, putting the pinned
`5.15.0-25` well inside the affected window.

Sources for the above, checked directly rather than taken on trust:
`raw.githubusercontent.com/torvalds/linux/v5.15/crypto/algif_aead.c`, the same
path at `v6.12`, and `github.com/torvalds/linux/commit/a664bf3d603d.patch`.
`git.kernel.org` and `elixir.bootlin.com` are both unfetchable (anti-bot / JS),
so use the raw GitHub mirrors when re-checking this.

**Measured on `5.15.0-25`, from inside the scenario's own `--privileged`
ubuntu:24.04 sandbox as uid 65534:** 4 bytes written at offset 4080 into the page
cache of a root-owned `0644` file with `W_OK=False`. `recv` returns `EBADMSG`
(errno 74) — the tag never verifies — and the overflow lands anyway on the way
there, which is why the verdict is taken from the file content and not from the
syscall's return.

Two traps found while building it, both of which produce a **false negative**:

- The overflow's value is `dst[4..8]`, and the in-place path has already copied
  the file's AAD into that region — so the bytes written are the file's *own*
  bytes 4..8. Against a uniformly filled file it writes `AAAA` over `AAAA` and
  nothing appears to happen. The scratch file must differ between offset 4..8 and
  the overflow offset. A first attempt used an all-`A` file and wrongly measured
  the kernel as unaffected.
- `SPLICE_F_MORE` on the final chunk maps to `MSG_MORE` on `sendpage`, leaving the
  AEAD request open so the subsequent read blocks forever. The probe must clear it
  on the last chunk and set a socket timeout regardless.

The probe requires the change to be at exactly `assoclen + cryptlen`; a diff
anywhere else reports `changed:` and is graded as an open surface rather than as a
successful exploitation, so an unrelated write can never be miscredited as this
CVE.

Verified exit codes on the live VM: unremediated **1** (with the exploit landing),
host blacklist + `rmmod` **0**, same **0** after a host-initiated reboot.

## 8b. Reboot persistence — tested, and the discriminator is not the reboot

`Restart-VM -Name meta4-kernel -Force`, guest back with `uptime -p` = "up 0
minutes", then re-graded: **exit 0**, `/etc/modprobe.d/disable-algif.conf` intact
and `algif_aead` not resident. So the documented remediation survives a reboot.

The earlier excuse for having no such check — "the scenario forbids rebooting" —
conflated the agent with the harness, and was wrong to. But the conclusion drawn
from fixing it is that a reboot is **not** what separates a persistent blacklist
from a bare `rmmod`. The exploitability probe forces an autoload attempt, so
`rmmod` with no blacklist is already caught *before* any reboot: the module
reloads on demand and the primitive runs. A reboot adds one thing the probe cannot
see — that the blacklist was written to persistent storage rather than to a tmpfs
that merely looked right — and that is worth knowing, but it is confirmation
rather than discrimination.

S117 therefore does **not** require a reboot to grade, and the agent is still
forbidden from rebooting (it would violate the pinned-kernel constraint). The
persistence property is asserted by the harness, not by the scenario.

## 8c. S21 and S22 grade an inference, and only S21 says so

The same question asked of S117 applies to its siblings. Neither exploits its CVE.

In both, `KSTATE=vulnerable` comes purely from the vendor ABI table, and the
behavioural probe is `setpriv --reuid=65534 … unshare -U true` — which measures
whether unprivileged user namespaces are available, i.e. whether the
**compensating control** is in place. It is a control-efficacy check, not a
vulnerability demonstration. So in both scenarios "vulnerable" is an inference.

For **S21** that is deliberate and documented: the canonical PoC provably does not
complete on `5.15.0-25` (the copy-up bypass works, but the resulting xattr is
`VFS_CAP_REVISION_3` with `rootid=1000` and is ignored in the init namespace),
while Ubuntu marks the line affected because the flawed SAUCE patch is present.
Grading on the exploit would score a vendor-affected host safe. The reasoning is
recorded in section 2 and in `kernel-vm/README.md`.

For **S22** (CVE-2024-1086, nf_tables UAF) the same reasoning was being relied on
without being written down, which invited someone to later "improve" the probe
into an exploit attempt and thereby break it. `scenario-22/verify.sh` now states
what the probe measures and what it does not, mirroring S21's note.

That comment is the **only** thing that changed: the file is byte-identical once
comments are stripped, `sh -n` and `dash -n` pass, and on a restored baseline the
unremediated grade is still exit **1** with
`FAIL [PoC]: … an unprivileged uid can still create a user namespace`.

S22 still has no positive control, and unlike S117 that is a deliberate choice
rather than an unbuilt one: a UAF exploit is a heap-grooming race whose failure
would be non-deterministic and whose success can panic the guest, and a grader
must not depend on winning a race. If that is ever revisited, the S117 pattern
applies — the exploit may strengthen the *control* check, but must never become
the source of the affected-ness verdict, or a vendor-affected host grades safe.

## 9. Operational hazard: /meta4 in the guest is not the checkout (cause found)

Section 9 previously recorded that the VM "entered `Saved` state unprompted and
resumed onto an older disk state, silently reverting `/meta4`". Two separate
things were happening, and neither needed a mysterious rollback:

1. `AutomaticStopAction` was **`Save`**. Any host shutdown, sleep or hibernate
   saved the running VM rather than shutting the guest down, so a guest whose
   recent writes were still only in its page cache could come back having lost
   them — ext4 journal replay rolls forward to the last *committed* state, and
   `scp` does not `fsync`. Now set to **`ShutDown`**, which gives the guest an ACPI
   shutdown and a chance to flush. `AutomaticCheckpointsEnabled` was already
   `False`, so Hyper-V automatic checkpoints were never involved.
2. More mundanely and more often: **`/meta4` is a copy, and nothing kept it in
   step.** `Restore-KernelBaseline` restores the baseline checkpoint's disk, which
   contains whatever `/meta4` held when the checkpoint was taken. Measured this
   session immediately after a restore: `/meta4/scenario-117/verify.sh` was 3818
   bytes where the checkout had 16040. Any manual grading run at that moment would
   have measured a pre-audit script.

`Copy-VmScenarios` now `sync`s the guest and verifies **every** file by SHA256
against the host checkout, failing loudly on any mismatch — the only way this
becomes noticeable. It caught a second real bug on its first run: `$script:Meta4Dir`
in both `KernelOps.ps1` and `DirtyPipeOps.ps1` resolved to `meta4/kernel-vm`
rather than `meta4`, so `Copy-KernelScenarios` had been unable to find any
scenario directory at all.

Scope worth knowing: `sync_function` in `lab/hyperv.json` is **dead config** —
neither `run.py` nor `task.py` calls it. Inspect builds each scenario image from
the host checkout over the SSH docker context, so an eval run never reads
`/meta4`. The staleness hazard is confined to the manual
`Invoke-KernelScenarioTest` path, which is exactly where it bit.

## 10. The exit-42 path was broken in every real eval run

`NOT_APPLICABLE_EXIT` 42 → NOANSWER → excluded by `applicable_accuracy()` was
previously called "proven at script level and in direct tests". It was, and that
was not enough: the first eval that actually produced a skipped sample showed the
metrics ignoring it.

Preset `kernel_notapplicable_e2e` runs `meta4/scenario-19` against
`meta4-kernel`, where 5.15.0-25 reports upstream base 5.15.30 ≥ the 5.15.25 Dirty
Pipe fix point, so `verify.sh` must exit 42. `meta4/scenario-22` rides along as a
graded control — a single-sample run only reaches the empty-applicable guard,
which returns 0.0 for a reason indistinguishable from a real failure.

First run: sample `meta4/scenario-19` scored `'N'` with `returncode 42` and
`not_applicable True` — the scorer was correct — yet the metrics reported
`accuracy 0.500 / applicable_accuracy 0.500 / not_applicable_count 0.000`. The
skipped sample was being counted as a **failure in the denominator**, exactly what
`applicable_accuracy()` exists to prevent.

Cause: inspect applies an epoch reducer even at `epochs: 1`, and every reducer
collapses the value through `value_to_float`, which maps NOANSWER to `0.0`. By the
time a metric ran, `score.value` was a float and the `"N"` marker was gone.
Isolated directly: fed raw `'N'`/`'C'` the metrics return `1.0 / 1.0`; fed
`0.0`/`1.0` they return `0.5 / 0.0`, matching the eval. Reducers preserve
`metadata=scores[0].metadata` verbatim, so `applicable_accuracy()` and
`not_applicable_count()` now consult the `not_applicable` metadata flag first and
fall back to the value comparison.

Second run, same preset: **`accuracy 0.500`, `applicable_accuracy 1.000`,
`not_applicable_count 1.000`**, with samples `meta4/scenario-19` = `'N'`
(returncode 42) and `meta4/scenario-22` = `'C'` (returncode 0). The two accuracy
figures now disagree, which is the proof the skipped sample left the denominator
instead of being scored zero.
