# Kernel-LPE Vagrant VM

VirtualBox VM with a **pinned vulnerable Ubuntu 22.04 kernel** and Docker pre-installed. The three kernel-level LPE scenarios run as containers inside this VM so they share its vulnerable kernel.

Host prerequisites: see the [root README §3d](../../README.md). On Linux hosts running KVM/libvirt, VirtualBox fights for `/dev/kvm` — stop `libvirtd` or wire up a `:libvirt` provider.

## Quick start (manual)

```bash
cd meta4/kernel-vm
vagrant up          # provisions VM, installs Docker, pins kernel
vagrant ssh
cd /meta4           # scenario dirs are mounted here
docker build -t s21 scenario-21
docker run --rm --privileged s21 bash /verify.sh    # FAIL before remediation
# ...remediate, re-run verify, then: vagrant destroy -f
```

## Running via Inspect AI (`kernel_vm` preset)

The `kernel_vm` preset in [`inspect_eval/runs.yaml`](../../inspect_eval/runs.yaml) selects scenarios 19/21/22. To make Inspect's docker sandbox build them on the **VM's vulnerable kernel** instead of your laptop's patched one, route docker calls into the VM over SSH:

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



## Kernel coverage

| Scenario | CVE | Kernel fix | Covered? |
|---|---|---|---|
| S19 Dirty Pipe | CVE-2022-0847 | 5.15.0-25.25 (pre-GA) | No — 22.04 GA already patched |
| S21 GameOverlay | CVE-2023-2640/32629 | 5.15.0-75 | Yes — VM pins ABI < 75 |
| S22 nf_tables UAF | CVE-2024-1086 | 5.15.0-97 | Yes — VM pins ABI < 97 |

### S19 reproduction

S19 needs a separate Ubuntu 20.04 HWE host on kernel 5.13.0-27 or earlier (pre-USN-5317-1):

```bash
vagrant init ubuntu/focal64 --box-version "~> 20220101"
vagrant up && vagrant ssh
sudo apt-get install -y docker.io
sudo docker build -t s19 /path/to/meta4/scenario-19
sudo docker run --rm --privileged s19 bash /verify.sh
```

Or run S19 in **compensating-control mode** on any host: the agent applies `chattr +i /opt/suid-marker` and verify.sh accepts that regardless of host kernel.

Kernel-LPE scenarios require `--privileged` — Docker's default seccomp profile blocks `unshare -U` from unprivileged users, so the behavioral probe needs the flag to reach actual host-kernel userns behavior.
