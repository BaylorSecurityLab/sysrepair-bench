# Kernel-LPE VM (Hyper-V)

Hyper-V VM with a **pinned vulnerable Ubuntu 22.04 kernel** (`5.15.0-25-generic`, ABI 25) and Docker pre-installed. **Three** kernel-level LPE scenarios run as privileged containers inside this VM so they share its vulnerable kernel.

Vagrant/VirtualBox has been retired — see `lab/KernelLab.ps1` and `lab/KernelOps.ps1`. Requires Hyper-V, an **elevated** PowerShell (Hyper-V cmdlets need it), `qemu-img` (`scoop install qemu`), and `oscdimg` from the Windows ADK Deployment Tools.

**Secure Boot is off, deliberately.** Ubuntu's shim revokes superseded signed kernels to prevent exactly the downgrade this VM performs on purpose; with it on, the guest never reaches the kernel.

## Scenario ownership

| scenario | CVE | this VM? |
|---|---|---|
| S21 GameOverlay | CVE-2023-2640/32629 | yes — jammy fix is `5.15.0-177.187`; we pin 25 |
| S22 nf_tables UAF | CVE-2024-1086 | yes — fixed at ABI 101 |
| S117 Copy Fail | CVE-2026-31431 | yes — jammy fix is `5.15.0-179.189`; we pin 25 |
| S19 Dirty Pipe | CVE-2022-0847 | **no** — see [`meta4/dirtypipe-vm`](../dirtypipe-vm) |

S19 moved out because 5.15.0-25 **already carries** the Dirty Pipe fix, so here it could only ever be graded through the `chattr +i` compensating control. `meta4/dirtypipe-vm` pins 20.04 HWE `5.13.0-27` — inside the affected window, since USN-5317-1 landed the fix at `5.13.0-35.40` — where the real exploit path is reachable.

## Build

```powershell
cd meta4\kernel-vm\lab
. .\KernelLab.ps1
Install-KernelLab     # image -> VHDX -> cloud-init seed -> provision -> baseline checkpoint
```

`Assert-KernelAbi` fails the build unless ABI 25 booted. That gate matters: a newer kernel silently stops S21/S22 being exploitable and `verify.sh` would then "pass" for the wrong reason.

## Quick start (manual)

```powershell
cd meta4\kernel-vm\lab
. .\KernelOps.ps1
Initialize-KernelHost                  # restore -> start -> portproxy -> ABI check
Copy-KernelScenarios                   # scp scenario-21/22/117 to /meta4 in the guest
Invoke-KernelScenarioTest scenario-21   # build + grade; exit 1 BEFORE remediation is correct
```

`verify.sh` is **bind-mounted**, not baked into the image:

```bash
docker run --rm --privileged -v /meta4/scenario-21/verify.sh:/verify.sh:ro s21 bash /verify.sh
```

None of these Dockerfiles `COPY verify.sh` — the Inspect harness writes it into the sandbox at scoring time (`scorer.py::_run_verify`). The older documented form, `docker run --privileged s21 bash /verify.sh`, exits **127** with "No such file or directory".

**Reading the result:** a pre-remediation **FAIL is correct** — it is the proof the CVE reproduces on this kernel. A pass before remediation means the scenario is exercising nothing.

## Running via Inspect AI (`kernel_e2e` preset)

`hyperv_vm: meta4/kernel-vm` makes `run.py` drive `lab/hyperv.json` → `Initialize-KernelHost`, then point `DOCKER_CONTEXT` at the VM over SSH, so images build and run on the **VM's** vulnerable kernel rather than the host's patched one:

```bash
cd inspect_eval
uv run python -m sysrepair_bench.run kernel_e2e      # scenarios 21/22/117
uv run python -m sysrepair_bench.run dirtypipe_e2e   # scenario 19, on the 5.13 VM
```

No manual `docker context` juggling is needed — `_ensure_vagrant_docker_host` writes the managed `~/.ssh/config` block and creates the context itself.

<details>
<summary>Legacy Vagrant instructions (retired — kept for reference only)</summary>

```bash
# 1. Bring the VM up (one-time per session).
cd meta4/kernel-vm && vagrant up

# 2. Capture the Vagrant-generated SSH config so docker can reach the VM.
vagrant ssh-config > kernel-vm.ssh

# 3. Register a docker context that tunnels into the VM. SSH host alias
#    `default` matches what `vagrant ssh-config` emits.
docker context create kernel-vm \
  --docker "host=ssh://default" \
  --description "meta4 kernel-LPE Vagrant VM"

# 4. Run the preset. SSH config flag points docker at the captured config;
#    DOCKER_CONTEXT pins this shell to the VM's daemon for the run only.
cd ../..
DOCKER_CONTEXT=kernel-vm \
SSH_OPTIONS="-F meta4/kernel-vm/kernel-vm.ssh" \
  uv run python -m sysrepair_bench.run kernel_vm

# 5. When done, drop back to local docker:
docker context use default
```

Notes:
- Container builds happen inside the VM; the agent loop, model API calls, and logs stay on your laptop.
- The first build is slow (SSH-tunneled `docker cp` of build context). Subsequent runs reuse the VM's image cache.
- If you only want to test compensating-control fixes (`chattr +i`, `kernel.unprivileged_userns_clone=0`), skip the VM entirely — the preset works against your laptop's docker and `verify.sh` accepts those fixes regardless of host kernel.

### Windows host (Docker Desktop)

Docker Desktop on Windows shells out to OpenSSH directly and ignores `SSH_OPTIONS` / `-F`. Wire the VM into `~/.ssh/config` instead so docker can resolve the hostname:

```powershell
# 1. Bring the VM up.
cd meta4\kernel-vm
vagrant up

# 2. Append Vagrant's SSH config to your user SSH config, renaming the host.
vagrant ssh-config |
  ForEach-Object { $_ -replace '^Host default', 'Host kernel-vm' } |
  Add-Content -Path $env:USERPROFILE\.ssh\config

# 3. Verify the alias works (should drop you into the VM).
ssh kernel-vm exit

# 4. Register the docker context using the alias.
docker context create kernel-vm `
  --docker "host=ssh://kernel-vm" `
  --description "meta4 kernel-LPE Vagrant VM"

# 5. Run the preset.
cd ..\..
$env:DOCKER_CONTEXT = "kernel-vm"
uv run python -m sysrepair_bench.run kernel_vm
Remove-Item Env:DOCKER_CONTEXT

# 6. (Optional) Tear down later.
cd meta4\kernel-vm; vagrant destroy -f
docker context rm kernel-vm
```

The `Host kernel-vm` block in `~/.ssh/config` already pins `IdentityFile` to Vagrant's insecure key and the right `Port`, so no other env vars are needed. If `~/.ssh/config` doesn't exist yet, create the parent dir first: `New-Item -ItemType Directory -Force $env:USERPROFILE\.ssh`.

</details>

## Kernel coverage

| Scenario | CVE | Kernel fix | Covered? |
|---|---|---|---|
| S19 Dirty Pipe | CVE-2022-0847 | 5.15.25 upstream; jammy GA `5.15.0-25` | No — already patched here; verify.sh exits 42 (SKIP) |
| S21 GameOverlay | CVE-2023-2640/32629 | `5.15.0-177.187` (jammy changelog reverts the SAUCE patch) | Yes — VM pins ABI 25 |
| S22 nf_tables UAF | CVE-2024-1086 | `5.15.0-101.111` (USN-6704-1) | Yes — VM pins ABI 25 |
| S117 Copy Fail | CVE-2026-31431 | `5.15.0-179.189` jammy; upstream 5.15.204 / 6.18.22 / 6.19.12 | Yes — VM pins ABI 25; passable from the sandbox (see below) |

### Why S21 grades on version, not on an exploit attempt

Some vulnerability databases mark jammy `5.15.0` **not-affected** by
CVE-2023-2640/32629 while Ubuntu's own tracker gives `Fixed 5.15.0-177.187`. Both
are describing something real, and the difference decides how the scenario must be
graded.

Measured on `5.15.0-25`: the OverlayFS copy-up permission check **is** bypassed —
an unprivileged uid successfully wrote `cap_setuid=eip` onto a real ext4 file. But
the resulting xattr is `VFS_CAP_REVISION_3` with `rootid=1000`, so it is honoured
only inside a user namespace owned by that uid and ignored in the init namespace;
`setuid(0)` returns EPERM. The flawed Ubuntu SAUCE patch is present — the fix at
177 is literally
`Revert "UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs"`,
and a patch cannot be reverted unless it was there — but the canonical PoC does not
yield root on this configuration.

So the host is vendor-affected while the exploit does not complete. **A behavioural
exploit attempt must therefore never be the verdict source here**: it would grade a
vendor-affected host as safe. The version/ABI check is the verdict; the behavioural
probe only distinguishes "mitigation applied" from "mitigation absent", and a
failure to set the probe up is treated as inconclusive rather than as "blocked".

### S117 grades the host kernel's module policy, not a file in the sandbox

`request_module()` runs the modprobe helper through `call_usermodehelper` in the
**initial** namespaces, against the **host** root filesystem — so a blacklist
written to the sandbox's own `/etc/modprobe.d` is inert, and grading that file
graded the wrong system.

The obvious conclusion — that the agent therefore cannot fix this — is wrong.
Measured on `5.15.0-25` from a `--privileged` sandbox with no host shell:
`/dev/sda1` is visible and mountable, so the host's `/etc/modprobe.d` is writable;
`rmmod` unloads host-wide because module unload is a global kernel operation; and
`/proc/sys/kernel/modprobe` and `kernel.modules_disabled` are writable and not
namespaced. The advisory's own workaround is performable exactly where the agent
runs, with no extra mount or compose change — a bind mount of `/etc/modprobe.d`
would grant nothing `--privileged` does not already grant while making the scenario
less faithful.

`verify.sh` grades three properties of the **host** kernel: **residency**
(`/proc/modules`), **exploitability** (the CVE's own primitive is attempted), and
**targeting** (`algif_skcipher` still autoloads). Targeting is what rejects the
blanket shortcuts: `kernel.modprobe=/bin/false` and `modules_disabled=1` both
close the AEAD surface while breaking every other module load, whereas the
advisory's workaround leaves dm-crypt, LUKS, kTLS, IPsec and the common crypto
libraries working. The probe no longer undoes the fix it grades — with the control
correct the bind cannot load anything, and with it absent the pre-probe residency
state is restored so a FAIL cannot poison the next run.

**Exploitability is a positive control, not a reachability proxy.** A refused bind
cannot tell "the AEAD socket is unreachable" from "the surface is open but the flaw
does not work here", so the verifier performs the actual 4-byte page-cache write as
uid 65534 against a root-owned `0644` scratch file, and requires it to land at
exactly `assoclen + cryptlen`. Confirmed on `5.15.0-25` inside the scenario's own
sandbox: 4 bytes at offset 4080, `recv` returning `EBADMSG`. The scratch file is
unlinked afterwards; no real binary is touched, and page-cache damage does not
survive a reboot in any case. See
[`KERNEL-VERSION-CHECKS.md`](../KERNEL-VERSION-CHECKS.md) §8a for the source
evidence that 5.15's `_aead_recvmsg()` and `authencesn.c` are unchanged from the
versions the advisory verified, and for the two false-negative traps in writing
such a probe.

Use `rmmod`, not `modprobe -r`: this image has no `/lib/modules` for the host
kernel, so `modprobe -r` fails with "Module algif_aead not found".

Verified exit codes: unremediated **1** (exploit lands); host blacklist + `rmmod`
done only inside the sandbox **0**; **0** again after `Restart-VM -Force`, so the
documented fix is reboot-persistent; unload without a host block **1** (the
autoload is forced, so `rmmod` alone is caught with no reboot needed); blacklist
written container-side only **1**; `kernel.modprobe=/bin/false` **1**;
unprivileged sandbox **42**; kernel changed against the recorded baseline **1**;
patched (6.6.200) or unprovable (5.19.17) host **42**.

A **seccomp** filter on `socket(AF_ALG, …)` — the advisory's other suggestion — is
not accepted as the fix here, because it configures a workload rather than the
host and would leave every process outside the filter exploitable. Grading is on
kernel state, so the blacklist's filename is irrelevant; the advisory's own example
name differs from `threat.md`'s and both pass.

### S19 reproduction — use `meta4/dirtypipe-vm`

S19 needs Ubuntu 20.04 HWE below `5.13.0-35` (USN-5317-1). That VM now exists and is built the same way as this one:

```powershell
cd meta4\dirtypipe-vm\lab
. .\DirtyPipeLab.ps1
Install-DirtyPipeLab          # asserts ABI 27 booted
```

```bash
cd inspect_eval
uv run python -m sysrepair_bench.run dirtypipe_e2e
```

Its `install-old-kernel.sh` fetches the kernel debs by **direct URL** — 5.13 HWE is EOL and superseded, so `apt-get install linux-image-5.13.0-27-generic` on a current focal resolves to something newer or nothing. Both debs must go in **one** `dpkg -i` call: `linux-modules-X` depends on `linux-image-X`, so installing them separately fails whichever order you try.

Compensating-control mode (`chattr +i /opt/suid-marker`) is accepted **only once the kernel is known to be vulnerable**. On a patched or unaffected host `verify.sh` exits 42 before reaching that branch, because `+i` there is a no-op and grading it as a fix would credit work nobody did. That is why the dedicated VM exists rather than running S19 anywhere.

**How the kernel state is decided (fixed — was broken).** `verify.sh` used to strip the Ubuntu ABI from `uname -r` (`5.15.0-25-generic` → `5.15.0`) and compare that to upstream `5.15.26`. Ubuntu backports into the **ABI**, not the point release, so the test could never pass and every `5.15.0-NN` was declared vulnerable — including this VM's patched kernel, which then scored CORRECT via `chattr +i`.

It now reads `/proc/version_signature` field 3 (the upstream stable base — the only Ubuntu-reported value comparable to a fix version, kernel-generated so a container sees the *host's*), backed by an ABI table because 5.13 reports `5.13.19` at both ABI 27 and 35. Cloud flavours are refused so `5.15.0-1057-azure` cannot satisfy "≥ 25", and anything pre-5.8 is `not_affected` outright since `PIPE_BUF_FLAG_CAN_MERGE` did not exist yet.

`meta4/lib/kernel-affected.sh` is the reference copy; the logic is inlined into `verify.sh` because the harness uploads that file to the sandbox alone. Keep the two in step. Remaining known gaps are in [`meta4/KERNEL-VERSION-CHECKS.md`](../KERNEL-VERSION-CHECKS.md).

Kernel-LPE scenarios require `--privileged` — Docker's default seccomp profile blocks `unshare -U` from unprivileged users, so the behavioral probe needs the flag to reach actual host-kernel userns behavior.
