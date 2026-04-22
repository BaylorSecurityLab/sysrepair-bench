# Kernel-LPE Vagrant VM

This directory provisions a VirtualBox VM with a **pinned vulnerable
Ubuntu 22.04 kernel** and Docker pre-installed. The three kernel-level
LPE scenarios run as containers inside this VM so they share its
vulnerable kernel.

## Host prerequisites

You need a host machine with hardware virtualization available to
VirtualBox. The VM itself is Ubuntu 22.04; the host can be Windows or
Linux.

### Windows 10 / 11

**BIOS/UEFI (one-time, reboot required):**
- Enable **Intel VT-x** / **AMD-V** (labelled "Virtualization Technology"
  or "SVM Mode" in most firmwares)
- Recommended: also enable **Intel VT-d** / **AMD-Vi** ("IOMMU")

**Turn OFF the Hyper-V stack.** VirtualBox can't get full hardware
virtualization while Hyper-V has claimed it. From an elevated
PowerShell:

```powershell
# Disable every feature that pulls in the hypervisor (ignore errors
# for features already off or unavailable on Home editions).
dism.exe /Online /Disable-Feature:Microsoft-Hyper-V-All /NoRestart
dism.exe /Online /Disable-Feature:VirtualMachinePlatform /NoRestart
dism.exe /Online /Disable-Feature:HypervisorPlatform /NoRestart
dism.exe /Online /Disable-Feature:Containers /NoRestart

# Force the hypervisor off at boot even if a stray feature flips back on.
bcdedit /set hypervisorlaunchtype off
```

Also open **Windows Security → Device security → Core isolation** and
turn **Memory Integrity OFF** — it's Virtualization-Based Security and
will block VT-x from reaching VirtualBox.

**Reboot** after the changes above.

> If you need WSL2 alongside VirtualBox, VirtualBox 7.1+ does work over
> the Windows Hypervisor Platform backend, but VM performance is
> noticeably slower. For kernel-level work we recommend disabling the
> Hyper-V stack entirely as above.

**Toolchain — Scoop-first.** Install [Scoop](https://scoop.sh) first:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex
```

Then install everything Scoop can give you:

```powershell
# Main bucket: git + vagrant
scoop install git vagrant

# VirtualBox lives in the "extras" bucket
scoop bucket add extras
scoop install virtualbox
```

Log out and back in (or open a new shell) so `VBoxManage` lands on PATH.
Verify:

```powershell
vagrant --version      # 2.4.x
VBoxManage --version   # 7.x
```

**Cannot be installed via Scoop — handle manually:**

| Item | How |
|---|---|
| BIOS virtualization (VT-x / AMD-V) | Firmware setup; see above |
| Hyper-V / Memory Integrity off | `dism` + Windows Security UI; see above |
| (Optional) VirtualBox Extension Pack | Only needed for USB 2/3 passthrough or PXE boot — not required for this VM. Download from [virtualbox.org](https://www.virtualbox.org/wiki/Downloads) and run `VBoxManage extpack install <file>.vbox-extpack` |

### Ubuntu / Debian (22.04+) host

```bash
# Make sure BIOS virtualization is enabled (same firmware-level step
# as the Windows guidance above).

sudo apt update
sudo apt install -y virtualbox vagrant

# Let your user talk to VirtualBox without sudo.
sudo usermod -aG vboxusers "$USER"
# Log out and back in for the group to take effect, then:

vagrant --version
VBoxManage --version
```

If the host already runs KVM/libvirt, VirtualBox will fight it for
`/dev/kvm`. Either stop the `libvirtd` service while you use this VM,
or switch to the `libvirt` Vagrant provider (not wired up in this
Vagrantfile — would require a `config.vm.provider :libvirt` block).

## Quick start

```bash
cd meta4/kernel-vm
vagrant up          # provisions VM, installs Docker, pins kernel
vagrant ssh

# Inside the VM — scenario directories are mounted at /meta4
cd /meta4

# Build and test a kernel scenario (should FAIL before remediation)
docker build -t s21 scenario-21
docker run --rm --privileged s21 bash /verify.sh

# Apply remediation inside the container, then re-run verify
```

## Kernel coverage matrix

| Scenario | CVE | Kernel fix | Covered by this VM? |
|---|---|---|---|
| S19 Dirty Pipe | CVE-2022-0847 | 5.15.0-25.25 (pre-GA) | **No** — 22.04 GA already includes the fix |
| S21 GameOverlay | CVE-2023-2640/32629 | 5.15.0-75 | **Yes** — VM pins ABI < 75 |
| S22 nf_tables UAF | CVE-2024-1086 | 5.15.0-97 | **Yes** — VM pins ABI < 97 |

## S19 (Dirty Pipe) — separate host required

Dirty Pipe was patched before Ubuntu 22.04 reached GA. To reproduce it
you need an Ubuntu **20.04** host running the HWE kernel **5.13.0-27**
or earlier (pre-USN-5317-1, February 2022):

```bash
# Example: Vagrant box with Ubuntu 20.04
vagrant init ubuntu/focal64 --box-version "~> 20220101"
vagrant up && vagrant ssh

# Inside the 20.04 VM, install Docker and run S19
sudo apt-get install -y docker.io
sudo docker build -t s19 /path/to/meta4/scenario-19
sudo docker run --rm --privileged s19 bash /verify.sh
```

Alternatively, run S19 in **compensating-control mode** on any host:
the agent applies `chattr +i /opt/suid-marker` and verify.sh accepts
that regardless of host kernel version.

## Container runtime flags

Kernel-LPE scenarios need elevated container privileges to interact with
the host kernel:

```bash
# Both probes try `unshare -U` as an unprivileged user inside the
# container; Docker's default seccomp profile blocks that syscall, so
# the behavioral check needs --privileged to reach the host kernel's
# actual userns behavior. Without --privileged, the probe reports
# "unshare blocked" due to container confinement, not a patched host.
docker run --rm --privileged s21 bash /verify.sh
docker run --rm --privileged s22 bash /verify.sh
```

## Tearing down

```bash
vagrant destroy -f
```
