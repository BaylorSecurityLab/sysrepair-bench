# SysRepair-Bench — Installation Guide

This guide walks through everything you need to install to run the full
benchmark, and **which host runs which suite**. It complements the high-level
"Set-up" section in [README.md](README.md) with concrete, copy-pastable
commands and a recommended multi-host split.

The benchmark spans **313 binary scenarios + 16 Hivestorm free-roam
scenarios** across three execution backends:

- **Linux containers** (ccdc, meta2, meta3/ubuntu, vulnhub, most of meta4,
  most of hivestorm) — run on a Linux Docker host.
- **Windows containers** (meta3/windows, hivestorm Windows scenarios) — run on
  a Windows host with Docker Desktop in *Windows containers* mode + Hyper-V
  isolation.
- **VirtualBox + Vagrant VMs** (meta4/kernel-vm, meta4/ad-vm, hivestorm
  scenario-13 AD-DC, hivestorm scenario-14 FreeBSD) — run on a host with
  Hyper-V **off**, because VirtualBox cannot share VT-x with the Hyper-V
  hypervisor on Windows.

Because Windows containers need Hyper-V **on** and VirtualBox needs Hyper-V
**off**, those two cannot coexist on the same Windows install. This is why we
recommend three hosts.

---

## Recommended host topology (3 hosts)

| Host | OS | Virt. | Hyper-V | Runs |
|---|---|---|---|---|
| **Host A — Linux Docker** | Ubuntu 22.04+ / Debian 12+ / Fedora 40+ | VT-x/AMD-V on | n/a | All Linux container suites; the Inspect AI harness; meta2 (requires Linux kernel for the Hardy `vsyscall` page) |
| **Host B — Windows containers** | Windows 10/11 Pro or Enterprise (or Win Server 2019+) | VT-x/AMD-V on | **ON** | meta3/windows (21), hivestorm Windows containers (03, 04, 05, 08, 11) |
| **Host C — Vagrant VMs** | Windows 10/11 Pro or Linux | VT-x/AMD-V on | **OFF** | meta4/kernel-vm (S19/S21/S22/S117), meta4/ad-vm (S01–S20), hivestorm scenario-13 (AD DC), hivestorm scenario-14 (FreeBSD) |

If you only have one machine, see [Single-host fallbacks](#single-host-fallbacks) below.

### Recommended specs

Sized for parallel evals plus headroom for Docker layer cache, Windows base images,
and concurrent VMs (the meta4/ad-vm lab brings up DC + CA + Kali simultaneously, ~8 GB
of guest RAM at peak). All storage figures assume **SSD/NVMe** — spinning disks make
the Win2019 box's first-boot sysprep painfully slow.

| Host | CPU | RAM | Storage | Notes |
|---|---|---|---|---|
| **Host A — Linux Docker** | 8 cores / 16 threads | 16 GB min, **32 GB recommended** | **200 GB SSD** | Docker layer cache + meta2 Hardy multi-stage build + ~250 container images grow fast under repeated runs. |
| **Host B — Windows containers** | 8 cores / 16 threads | 16 GB min, **32 GB recommended** | **150 GB SSD** | Windows Server Core ltsc2019 base is ~5 GB. Hyper-V isolation utility-VM overhead is real — don't go below 16 GB. |
| **Host C — Vagrant VMs** | 6 cores min, 8 recommended | 16 GB min, **32 GB recommended** | **250 GB SSD** | meta4/ad-vm peaks at ~8 GB guest RAM (3 concurrent VMs). Win2019 + FreeBSD + Ubuntu Vagrant boxes total ~40 GB before snapshots. |

### Suite → host mapping

| Suite | Host A (Linux+Docker) | Host B (Win+Hyper-V) | Host C (Vagrant) |
|---|:-:|:-:|:-:|
| `ccdc/` (50) | ✅ | | |
| `meta2/` (40) | ✅ (Linux only) | | |
| `vulnhub/` (30) | ✅ | | |
| `meta3/ubuntu/` (19) | ✅ | | |
| `meta3/windows/` (21) | | ✅ | |
| `meta4/` Docker (117) | ✅ | | |
| `meta4/kernel-vm/` (S19, S21, S22, S117) | | | ✅ |
| `meta4/ad-vm/` (S01–S20) | | | ✅ |
| `hivestorm/` Linux (01, 02, 06, 07, 09, 10, 12, 15, 16) | ✅ | | |
| `hivestorm/` Windows containers (03, 04, 05, 08, 11) | | ✅ | |
| `hivestorm/scenario-13-ad-dc-win2019` | | | ✅ |
| `hivestorm/scenario-14-freebsd13` | | | ✅ |

The Inspect AI harness can drive any backend; install it on whichever host
will launch the runs. For the Vagrant scenarios it talks to the VM via an SSH
bridge container — see [hivestorm/scenario-13-ad-dc-win2019/README.md](hivestorm/scenario-13-ad-dc-win2019/README.md).

---

## Host A — Linux + Docker (the workhorse)

Covers every Linux container suite plus the Inspect AI harness. **meta2 must
run here** (Hardy's `vsyscall` page is unavailable on Docker Desktop / WSL2
kernels).

### A1. System prerequisites

Use your distro's package manager — never curl-install when an apt/dnf
package exists.

**Ubuntu 22.04+ / Debian 12+:**

```bash
sudo apt update
sudo apt install -y \
    git curl ca-certificates jq bash \
    docker.io docker-buildx \
    python3 python3-venv
sudo usermod -aG docker "$USER"   # log out / back in afterwards
```

**Fedora 40+ / RHEL 9+:**

```bash
sudo dnf install -y \
    git curl ca-certificates jq bash \
    docker docker-buildx \
    python3
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Verify Docker can run rootless from your account:

```bash
docker run --rm hello-world
```

### A2. `uv` for the Inspect AI harness

`uv` manages the Python env and lockfile. Use the official installer (no
distro package yet):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
exec "$SHELL"   # reload PATH
```

### A3. Clone + harness install

```bash
git clone <repo-url> sysrepair-bench
cd sysrepair-bench/inspect_eval
uv sync           # creates .venv, installs Inspect AI + providers
cd ..
```

### A4. Pre-build the meta2 Hardy base (optional)

The harness builds it on first run, but you can pre-warm it:

```bash
docker build -t sysrepair/meta2-hardy:latest meta2/_base
```

### A5. Regenerate hivestorm identities (every run)

Hivestorm scenarios randomize backdoor accounts, trojan paths, SUID plants,
rogue crons, and the legit admin name at build time. **Run this before every
hivestorm session** (Linux *and* Windows containers — Host B reads the same
`build/roles.json`):

```bash
bash hivestorm/prepare.sh            # all 16 scenarios, random seed
SEED=42 bash hivestorm/prepare.sh    # reproducible
bash hivestorm/prepare.sh 01         # single scenario
```

On Windows hosts use the PowerShell port:

```powershell
pwsh hivestorm/prepare.ps1
```

### A6. Smoke test

```bash
cd inspect_eval
uv run python -m sysrepair_bench.run smoke
```

---

## Host B — Windows containers (Hyper-V ON)

Runs the Windows-container scenarios (`meta3/windows/` and
hivestorm Windows scenarios). Cannot run VirtualBox/Vagrant.

### B1. Enable Hyper-V + Containers

Elevated PowerShell:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName Containers -All -NoRestart
Restart-Computer
```

After reboot, confirm:

```powershell
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
Get-WindowsOptionalFeature -Online -FeatureName Containers
```

### B2. Tooling via Scoop

[Scoop](https://scoop.sh) is the package manager we use on Windows — it does
not need admin rights and pins versions cleanly.

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex

scoop install git python uv jq
scoop bucket add extras
scoop install docker docker-compose
```

(Docker Desktop is also fine — install via its MSI if you prefer. Scoop's
`docker` package gives you the CLI + dockerd; pair with the Hyper-V backend.)

### B3. Switch Docker to Windows containers + Hyper-V isolation

- **Docker Desktop:** right-click tray → *Switch to Windows containers*.
- **Native dockerd:** add `"exec-opts": ["isolation=hyperv"]` to
  `%ProgramData%\docker\config\daemon.json` and restart the Docker service.

The harness auto-injects `isolation: hyperv` for every Windows-container
scenario, so manual flags are only needed for ad-hoc `docker run` outside the
harness.

### B4. Clone + harness install

```powershell
git clone <repo-url> sysrepair-bench
cd sysrepair-bench\inspect_eval
uv sync
cd ..
```

### B5. Smoke test

```powershell
docker run --rm mcr.microsoft.com/windows/servercore:ltsc2019 cmd /c ver
cd inspect_eval
uv run python -m sysrepair_bench.run hivestorm_windows   # or your preset of choice
```

---

## Host C — VirtualBox + Vagrant (Hyper-V OFF)

> **`meta4/ad-vm/` no longer belongs here.** The Active Directory lab was ported
> to Hyper-V + AutomatedLab — see [Host D](#host-d--active-directory-lab-on-hyper-v-hyper-v-on).
> Host C still covers `meta4/kernel-vm/` and hivestorm 13/14 until those move too.

Runs the remaining VM-backed scenarios: `meta4/kernel-vm/` and hivestorm
scenarios 13 and 14. Can be a Windows or Linux machine; we describe both.

### C1. Disable Hyper-V (Windows hosts only)

VirtualBox cannot share VT-x with Hyper-V. From elevated PowerShell:

```powershell
dism.exe /Online /Disable-Feature:Microsoft-Hyper-V-All /NoRestart
dism.exe /Online /Disable-Feature:VirtualMachinePlatform /NoRestart
dism.exe /Online /Disable-Feature:HypervisorPlatform /NoRestart
dism.exe /Online /Disable-Feature:Containers /NoRestart
bcdedit /set hypervisorlaunchtype off
```

Then: **Windows Security → Device security → Core isolation → Memory Integrity OFF**, and reboot.

Verify the hypervisor is gone:

```powershell
systeminfo | Select-String "Hyper-V"
# Expect: "A hypervisor has been detected... will not be displayed."
```

### C2. Install VirtualBox + Vagrant

**Windows (via Scoop):**

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex

scoop install git
scoop bucket add extras
scoop install virtualbox vagrant
```

**Ubuntu / Debian:**

```bash
sudo apt update
sudo apt install -y virtualbox vagrant git
sudo usermod -aG vboxusers "$USER"   # log out / back in afterwards
```

**Fedora:**

```bash
sudo dnf install -y @virtualization VirtualBox vagrant git
sudo usermod -aG vboxusers "$USER"
```

Verify:

```bash
vagrant --version       # ≥ 2.4.x
VBoxManage --version    # ≥ 7.0
```

### C3. Vagrant plugins

Several scenarios need the `vagrant-reload` plugin to chain reboots into
provisioners (AD DC promotion, kernel pinning, etc.). Install once per host:

```bash
vagrant plugin install vagrant-reload
```

### C4. Bring up a VM scenario

**meta4/kernel-vm (kernel-coupled LPE):**

```bash
cd meta4/kernel-vm
vagrant up                 # Ubuntu 22.04, kernel pinned pre-fix, Docker preinstalled
vagrant ssh
```

**meta4/ad-vm (AD lab — DC, CA, Kali attacker):**

```bash
cd meta4/ad-vm
vagrant up dc              # expect a WinRM timeout the first time — that's normal
vagrant up ca
vagrant up kali
```

See [meta4/ad-vm/README.md](meta4/ad-vm/README.md) for the full bringup
sequence.

**hivestorm scenario-13 (AD DC):**

```bash
bash hivestorm/prepare.sh 13
cd hivestorm/scenario-13-ad-dc-win2019
vagrant up                 # ~15 min first boot (ADDS promote + reboot + seed)
```

**hivestorm scenario-14 (FreeBSD 13):**

```bash
bash hivestorm/prepare.sh 14
cd hivestorm/scenario-14-freebsd13
vagrant up                 # ~5–8 min first boot
```

The Inspect AI harness reaches these VMs via an auto-built bridge container —
no manual networking required.

### C5. Optional: harness on the same host

If you want to drive the VMs from this same host, install `uv` + run
`uv sync` in `inspect_eval/` exactly as in [Host A step A2–A3](#a2-uv-for-the-inspect-ai-harness).

---

## Host D — Active Directory lab on Hyper-V (Hyper-V ON)

Runs `meta4/ad-vm/` — 20 Active Directory scenarios on a four-machine lab.
This replaces the Vagrant/VirtualBox path described in Host C.

Because Hyper-V must be **on** here and **off** for Host C, these two cannot be
the same machine until `kernel-vm` and hivestorm 14 are also ported. Host D can
share a machine with Host B (Windows containers), which also wants Hyper-V on.

Every step below is elevated PowerShell unless noted. Versions are the ones
this was built and verified against.

### D1. Enable Hyper-V

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All
# reboot
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All | Select-Object State
# Expect: Enabled
```

Requires Windows 10/11 **Pro**, Enterprise or Education. Home does not ship
Hyper-V.

### D2. PowerShell modules

```powershell
Install-Module Pester       -MinimumVersion 5.0.0 -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module AutomatedLab -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck
```

Verified against **Pester 6.0.1** and **AutomatedLab 5.61.0**. Record the
AutomatedLab version in `meta4/ad-vm/lab/IMAGES.md` — the lab definition uses
its role API, which does change between majors.

### D3. Windows ADK — Deployment Tools only

Provides `oscdimg`, used to build the cloud-init seed ISO for the attacker VM.

Download the ADK from
<https://learn.microsoft.com/windows-hardware/get-started/adk-install>, and in
the feature list **untick everything except "Deployment Tools"** — roughly a
100 MB install instead of several GB.

```powershell
# The ADK does not add oscdimg to PATH. Confirm it landed:
Get-ChildItem 'C:\Program Files (x86)\Windows Kits' -Recurse -Filter oscdimg.exe |
    Where-Object FullName -like '*amd64*' | Select-Object -ExpandProperty FullName
```

The harness locates it under Windows Kits automatically; you do not need to
add it to PATH.

### D4. LabSources — create this BEFORE importing AutomatedLab

```powershell
$base = 'C:\LabSources'
foreach ($d in 'ISOs','OSUpdates','PostInstallationActivities','Tools',
                'SoftwarePackages','CustomRoles','LabScripts') {
    New-Item -ItemType Directory -Path (Join-Path $base $d) -Force | Out-Null
}
Import-Module AutomatedLab
Get-LabSourcesLocation      # Expect: C:\LabSources
```

**Order matters.** `Import-Module AutomatedLab` resolves its LabSources
location during import and fails with *"Cannot bind argument to parameter
'Path' because it is null"* when the folder is absent — so you cannot use
`New-LabSourcesFolder` to create it. `lab/SysRepairLab.ps1` does this for you;
the manual form is here for diagnosis.

### D5. Installation media

Place both ISOs in `C:\LabSources\ISOs\`:

| ISO | Source | Size |
|---|---|---|
| Windows Server 2019 evaluation | <https://www.microsoft.com/evalcenter/download-windows-server-2019> — choose **ISO**, 64-bit English | ~5.3 GB |
| Ubuntu Server 24.04 LTS | <https://releases.ubuntu.com/24.04/> — `*-live-server-amd64.iso` | ~3.0 GB |

Then verify against the recorded hashes:

```powershell
cd meta4\ad-vm
. .\lab\Test-ImageChecksums.ps1
Test-ImageChecksums -ManifestPath .\lab\IMAGES.md -ImageDir 'C:\LabSources\ISOs'
```

If you obtained different builds, update `lab/IMAGES.md` with your own hashes
from `Get-ChildItem C:\LabSources\ISOs\*.iso | Get-FileHash -Algorithm SHA256`.

**Edition string.** `Install-Lab` exact-matches `-OperatingSystem`. The
evaluation media reports `Windows Server 2019 Datacenter Evaluation (Desktop
Experience)` — note *Evaluation*, which the retail spelling omits. Check yours:

```powershell
Get-LabAvailableOperatingSystem -Path C:\LabSources\ISOs |
    Select-Object OperatingSystemName, Version
```

and set `$osName` in `lab/SysRepairLab.ps1` to match. The script's preflight
prints the available list if it does not.

### D6. Host WinRM remoting — read before running

AutomatedLab **requires** `TrustedHosts = '*'` and CredSSP delegation to
`WSMAN/*`. This is not configurable: `AutomatedLabCore.psm1` throws
*"TrustedHosts need to be set to '*' in order to be able to connect to the new
VMs"*, and a subnet-scoped TrustedHosts list does not satisfy its precheck.

Understand what this changes before accepting it:

- **`TrustedHosts = '*'`** — the host will authenticate to *any* WinRM endpoint
  over NTLM without mutual authentication.
- **CredSSP client auth with fresh-credential delegation to `WSMAN/*`** — your
  credentials can be delegated to any host you connect to.

On a dedicated lab machine this is normal. On a machine you also use for other
work, weigh it.

```powershell
Enable-LabHostRemoting -Force
Test-LabHostRemoting          # Expect: True
```

To revert afterwards:

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '' -Force
Set-Item WSMan:\localhost\Client\Auth\CredSSP -Value $false -Force
Remove-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Recurse -Force
```

### D7. Docker, for the attacker tooling image

Docker Desktop in **Linux containers** mode. Verified against 29.4.0.

```powershell
cd meta4\ad-vm
docker build -t srb-attacker:1 .\lab\attacker
# Expect: tool gate: all 16 scenario dependencies resolve AND execute
```

The build fails loudly if any tool a `verify-poc.sh` invokes is missing or
cannot run. That gate is deliberate — a missing grader tool used to be graded
as "attack blocked", i.e. a pass on a vulnerable box.

### D8. Virtual switches

```powershell
cd meta4\ad-vm
. .\lab\New-LabSwitches.ps1

# Internal switches only, if the host's sole live adapter is the one you are
# working over -- creating an External switch on it briefly drops connectivity.
New-LabSwitches -SkipExternal

Get-LabSwitchHealth      # SRB-Lab 10.20.30.1, SRB-Kernel 10.20.40.1, both Private
Test-NoLabNatCollision   # Hyper-V allows one NAT prefix per host; WSL2 usually owns it
```

`SRB-Build` (External) is only needed while baking the attacker VM. Create it
then, naming the adapter explicitly:

```powershell
Get-NetAdapter -Physical | Where-Object Status -eq 'Up'
New-LabSwitches -ExternalAdapterName '<adapter>'
```

### D9. Build the lab

```powershell
cd meta4\ad-vm
powershell -ExecutionPolicy Bypass -File .\lab\SysRepairLab.ps1   # 45-90 min

. .\lab\Protect-ParentDisk.ps1
Set-LabVMHardening -VMName corp-dc01,corp-ca01,corp-ws01
Protect-ParentDisk -ParentVhdxPath (Get-LabParentDiskPath -VMName corp-dc01)
```

`Set-LabVMHardening` is not optional. It disables automatic checkpoints — which
client Hyper-V takes on *every VM start*, reintroducing exactly the live-state
DC snapshot the cold-baseline model exists to avoid — switches checkpoint type
to Standard, and pins fixed memory on the DC and attacker.

### D10. Attacker VM

```powershell
. .\lab\New-AttackerVM.ps1

New-AttackerSshKey                       # host-side probes use key auth, not passwords
New-CloudInitSeedIso -CloudInitDir .\lab\attacker\cloud-init -OutputIsoPath C:\srb\seed.iso
New-AttackerVM -UbuntuIsoPath C:\LabSources\ISOs\ubuntu-24.04.2-live-server-amd64.iso `
               -VhdxPath      C:\srb\attacker01.vhdx `
               -SeedIsoPath   C:\srb\seed.iso

Start-VM attacker01
# Complete the Ubuntu install. The VM sits on SRB-Build (internet) on purpose:
# cloud-init installs docker.io. Note its DHCP address from the console.

Install-AttackerTooling -BuildHost <dhcp-address>
Move-AttackerToLabNetwork
Start-VM attacker01
```

### D11. Provision, baseline, verify

```powershell
$cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator',
    (ConvertTo-SecureString 'Password1!' -AsPlainText -Force))

Invoke-Command -VMName corp-dc01 -Credential $cred -FilePath .\provision\seed-directory.ps1
Invoke-Command -VMName corp-ca01 -Credential $cred -FilePath .\provision\ca-postinstall.ps1

Import-Module .\lab\LabReadiness.psm1 -Force
. .\lab\Start-LabOrdered.ps1
. .\lab\Save-LabBaseline.ps1
. .\lab\Test-LabEgress.ps1

Start-LabOrdered      # ordered boot, clocks verified
Test-LabEgress        # must confirm NO internet reachable from attacker01
Save-LabBaseline      # atomic across all four machines

Invoke-Pester .\tests -Output Detailed
```

### D12. Run a scenario

```bash
./run-scenario.sh 13                    # restore -> inject -> handoff
./run-scenario.sh 13 --verify-only      # grade; exits 0 iff both gates pass
```

### Known gotchas

| Symptom | Cause |
|---|---|
| `Import-Module AutomatedLab` throws *"Cannot bind argument to parameter 'Path'"* | `C:\LabSources` does not exist. See D4 — create it first. |
| `Install-Lab`: *"could not be found in the available operating systems"* | `$osName` does not exactly match the ISO's edition string. See D5. |
| `Install-Lab` dies with *"PromptForChoice ... Object reference not set"* | AutomatedLab is trying to prompt from a non-interactive host. Run `Enable-LabHostRemoting -Force` first (D6). |
| `New-CloudInitSeedIso`: *"oscdimg.exe not found"* | ADK Deployment Tools not installed, or installed without that feature. See D3. |
| Attacker VM boots with no SSH key and no static IP; every probe times out | Seed ISO built without Joliet, so cloud-init saw `USER-DATA` rather than `user-data`. The harness passes `-j1`; if building by hand, do the same. |
| `docker build` fails at the tool gate | A tool some `verify-poc.sh` invokes is missing. That is the gate working — fix the image, do not remove the check. |

## Model provider credentials

The harness needs at least one provider. Set env vars on whichever host runs
the harness:

| Provider | Env var(s) |
|---|---|
| OpenAI / OpenAI-compatible (vLLM, Ollama, LM Studio) | `OPENAI_API_KEY` (any non-empty string for local), optionally `OPENAI_BASE_URL` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Google Gemini | `GOOGLE_API_KEY` |
| Hugging Face Inference | `HF_TOKEN` |

Drop them into `inspect_eval/.env` (auto-loaded by the run script).

---

## Single-host fallbacks

If you only have one machine, you can still run a meaningful subset:

- **Linux only:** all Linux containers + meta4/kernel-vm + meta4/ad-vm +
  hivestorm 13/14 (Vagrant works fine on Linux). You **cannot** run
  meta3/windows or hivestorm Windows containers — those need a Windows kernel.
- **Windows only, Hyper-V ON:** Linux containers (via Docker Desktop's WSL2
  backend) + Windows containers. You **cannot** run the Vagrant VM scenarios
  reliably while Hyper-V owns VT-x.
- **Windows only, Hyper-V OFF:** Vagrant VM scenarios only. Docker Desktop
  for Windows containers won't work without Hyper-V.

For dual-mode work on a single Windows box, you can toggle Hyper-V off/on
between sessions using `bcdedit /set hypervisorlaunchtype off` (or `auto`)
and rebooting — but it's friction; two boxes is much easier.

---

## Verification checklist

Run these on each host once setup is complete:

| Host | Check | Expected |
|---|---|---|
| A | `docker run --rm hello-world` | `Hello from Docker!` |
| A | `cd inspect_eval && uv run python -m sysrepair_bench.run smoke` | one scenario passes verify |
| B | `docker run --rm mcr.microsoft.com/windows/servercore:ltsc2019 cmd /c ver` | Windows version banner |
| C | `VBoxManage --version && vagrant --version` | both report ≥ supported versions |
| C | `vagrant plugin list` | shows `vagrant-reload` |
