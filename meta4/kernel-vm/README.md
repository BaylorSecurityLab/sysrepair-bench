# Kernel-LPE VM (Hyper-V)

Hyper-V VM with a **pinned vulnerable Ubuntu 22.04 kernel** (`5.15.0-25-generic`, ABI 25) and Docker pre-installed. **Three** kernel-level LPE scenarios run as privileged containers inside this VM so they share its vulnerable kernel.

Vagrant/VirtualBox has been retired — see `lab/KernelLab.ps1` and `lab/KernelOps.ps1`. Requires Hyper-V, an **elevated** PowerShell (Hyper-V cmdlets need it), `qemu-img` (`scoop install qemu`), and `oscdimg` from the Windows ADK Deployment Tools.

**Secure Boot is off, deliberately.** Ubuntu's shim revokes superseded signed kernels to prevent exactly the downgrade this VM performs on purpose; with it on, the guest never reaches the kernel.

## Scenario ownership

| scenario | CVE | this VM? |
|---|---|---|
| S21 GameOverlay | CVE-2023-2640/32629 | yes — fixed at ABI 75, we pin 25 |
| S22 nf_tables UAF | CVE-2024-1086 | yes — fixed at ABI 97 |
| S117 Copy Fail | CVE-2026-31431 | yes — never backported to 5.15.x |
| S19 Dirty Pipe | CVE-2022-0847 | **no** — see [`meta4/dirtypipe-vm`](../dirtypipe-vm) |

S19 moved out because 5.15.0-25 **already carries** the Dirty Pipe fix, so here it could only ever be graded through the `chattr +i` compensating control. `meta4/dirtypipe-vm` pins 20.04 HWE `5.13.0-27` — the last ABI before USN-5317-1 — where the real exploit path is reachable.

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
| S19 Dirty Pipe | CVE-2022-0847 | 5.15.0-25.25 (pre-GA) | No — 22.04 GA already patched |
| S21 GameOverlay | CVE-2023-2640/32629 | 5.15.0-75 | Yes — VM pins ABI < 75 |
| S22 nf_tables UAF | CVE-2024-1086 | 5.15.0-97 | Yes — VM pins ABI < 97 |
| S117 Copy Fail | CVE-2026-31431 | 6.18.22 / 6.19.12 / 7.0 | Yes — fix not backported to 5.15.x; VM's pinned kernel is vulnerable |

### S19 reproduction — use `meta4/dirtypipe-vm`

S19 needs Ubuntu 20.04 HWE on `5.13.0-27` or earlier (pre-USN-5317-1). That VM now exists and is built the same way as this one:

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

Compensating-control mode still works on any host (the agent applies `chattr +i /opt/suid-marker` and `verify.sh` accepts it regardless of kernel) — but that grades the mitigation, not the CVE, which is why the dedicated VM exists.

**Caveat on this table's `Covered?` column for S19:** `verify.sh` decides "vulnerable" from `uname -r` with the ABI stripped (`5.15.0-25-generic` → `5.15.0`), then compares against upstream `5.15.26`. Ubuntu backports fixes into the **ABI**, not the point release, so a patched 22.04 GA kernel is reported vulnerable. The check cannot distinguish patched from unpatched on any Ubuntu `5.15.0-NN`. Not yet fixed — it changes grading on every Ubuntu host.

Kernel-LPE scenarios require `--privileged` — Docker's default seccomp profile blocks `unshare -U` from unprivileged users, so the behavioral probe needs the flag to reach actual host-kernel userns behavior.
