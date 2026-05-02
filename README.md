# SysRepair-Bench: A Benchmark for AI Agents' Ability to Remediate Real-World System Vulnerabilities

## Overview

SysRepair-Bench evaluates autonomous agents on their ability to **remediate** misconfigurations, vulnerable dependencies, unsafe permissions on real systems. Each scenario is a reproducible Docker container/ Virtual Machine seeded with a known-vulnerable state drawn from public red-team material (CCDC hardening checklists, the Metasploitable 2 OpenVAS report, VulnHub VM write-ups, the Metasploitable 3 OpenVAS report, Hivestorm, Newly Designed Metasploitable 4).

For each scenario, given only the running container and Optional(threat description), an agent must perform system-administration actions (edit configuration, install/remove packages, adjust permissions, manage services, etc.) until:

1. **PoC check** — the original vulnerability is no longer exploitable, AND
2. **Regression check** — the affected service still functions correctly.

Remediation is scored as successful **only if both checks pass**.

The benchmark comprises **313 scenarios across five VM classes** (six suites): `ccdc/` (50), `meta2/` (40), `vulnhub/` (30), `meta3/ubuntu/` (19), `meta3/windows/` (21), and `meta4/` (137, comprising 117 Docker container scenarios + 20 Active Directory VM scenarios) — plus a **16-scenario `hivestorm/` free-roam track** that ships alongside the binary-pass/fail suites and uses weighted partial-credit scoring.

| VM Class / Suite | Era | Built | Source |
|---|---|---|---|
| [`ccdc/`](ccdc/) | 2015–2022 | 50 | CCDC blue-team hardening scripts (TAMU linuxmonkeys, LATech/UTSA SWCCDC, team checklists) on Ubuntu 25.10 |
| [`meta2/`](meta2/) | 2008–2012 | 40 | OpenVAS scan of Metasploitable 2.0 on Ubuntu 8.04. ⚠ **Linux host only** (see Host Requirements) |
| [`vulnhub/`](vulnhub/) | 2012–2022 | 30 | Per-VM vulnerability rebuilds (Kioptrix, DC-series, Mr-Robot, SickOs, Symfonos, etc.) on Debian 11 |
| [`meta3/ubuntu/`](meta3/ubuntu/) | 2014–2020 | 19 | Port of Rapid7 Metasploitable 3 (Ubuntu 14.04) — Drupalgeddon, ProFTPD mod_copy, payroll_app, Docker group escalation, WEBrick, UnrealIRCd, Samba, phpMyAdmin. Vendors the Rapid7 Chef cookbook under BSD-3. |
| [`meta3/windows/`](meta3/windows/)| 2016–2020 | 21 | Rapid7 Metasploitable 3 (Windows Server) — Struts, Jenkins, ManageEngine, GlassFish, Tomcat, ElasticSearch, IIS WebDAV, SMB. Scoped by the [Windows OpenVAS scan](openvas-scan-reports/metasploitable-3.0-win-openvas.pdf). ⚠ **Windows host only** (see Host Requirements) |
| **[`meta4/`](meta4/)** | 2022–2026 | 137 | Container suite (117 Docker scenarios) covering modern CVEs (Log4Shell family, Spring4Shell, PwnKit, Dirty Pipe, GameOver(lay), regreSSHion, Leaky Vessels, XZ backdoor, Copy Fail CVE-2026-31431, crAPI/DVGA/VAmPI API surfaces, LocalStack/MinIO/ArgoCD/k3s cloud-on-localhost misconfigs, ImageMagick, Memcached, curl SOCKS5, Redis Lua sandbox, Adminer, Apache Solr, Rsync, Cacti, and more) plus an **Active Directory VM lab** ([`meta4/ad-vm/`](meta4/ad-vm/), 20 scenarios: Zerologon, NoPac, ADCS ESC1–ESC8, Kerberoasting, DCSync, PrintNightmare, PetitPotam, and more). Kernel-coupled scenarios ship a Vagrant VM ([`meta4/kernel-vm/`](meta4/kernel-vm/)). |
| [`hivestorm/`](hivestorm/) | HS20–HS23 | 16 | **Free-roam** Hivestorm-style scenarios (Debian/Ubuntu/CentOS/Windows Server-Core/FreeBSD/AD-DC). Identities (backdoor account, trojan path, rogue cron, SUID plant) are randomized per build; the scorer emits weighted partial credit via JSONL checks rather than binary pass/fail. |

### Vulnerability categories

Every scenario's **(expect hivestorm)** `threat.md` is labeled with one of **five operational remediation categories** that mirror how security-operations teams classify remediation work:

1. **Access Control** — authentication, authorization, user privileges, file ownership. Typical actions: `chmod`, `chown`, `usermod`, `passwd`, `visudo`, `sshd_config`, PAM.
2. **Configuration Hardening** — insecure defaults, missing security directives, misconfigured service parameters. Typical actions: edits to `nginx.conf`, `sshd_config`, `my.cnf`, `apache2.conf`, `pg_hba.conf`, followed by `systemctl reload`/`restart`.
3. **Dependency & Package Management** — outdated packages with known CVEs, inherently compromised services, unnecessary high-risk daemons. Typical actions: `apt-get upgrade`, `--only-upgrade`, `remove`, `systemctl disable`.
4. **Network Security & Firewall Policy** — exposed ports, missing firewall rules, unrestricted listener scope. Typical actions: `ufw`, `iptables`, bind-address changes, TCP wrappers, `netstat`/`ss` auditing.
5. **Compensating Controls**, This covers vulnerabilities where direct remediation is not possible or not desirable — the package cannot be upgraded because a dependent legacy app requires the specific version, the software is end-of-life with no vendor patch, or the service cannot be restarted during business hours. The agent must instead apply network-level restrictions (firewall scoping, bind-to-localhost), application-layer mitigations (WAF rules, `mod_rewrite` guards, ACLs), or safe config-directive removals while keeping the service usable. Scoring adds a third dimension: **compensating-control adequacy** — whether the applied controls meaningfully reduce the attack surface.

### Severity distribution

Distribution of base severity scores across all 313 scenarios. Scores follow CVSS v3.1; scenarios without a CVE (CCDC misconfigs, Hivestorm free-roam) are unscored.

| Severity | CVSS v3.1 Range | # Scenarios |
|---|---|---|
| Critical | 9.0–10.0 | 93 |
| High | 7.0–8.9 | 107 |
| Medium | 4.0–6.9 | 44 |
| Low | 0.1–3.9 | 1 |
| Unscored (misconfig / free-roam) | — | 68 |
| **Total** | | **313** |

### Remediation category distribution

| Remediation Category | # Scenarios |
|---|---|
| Configuration Hardening | 111 |
| Dependency & Package Management | 53 |
| Access Control | 59 |
| Compensating Controls | 55 |
| Network Security | 19 |
| Free-roam (multiple) | 16 |
| **Total** | **313** |

### Service / application type distribution

| Service / Application Type | # Scenarios |
|---|---|
| Web Server | 59 |
| Enterprise / Infrastructure | 34 |
| System / Auth | 31 |
| Container / Runtime | 18 |
| Database / Cache | 19 |
| SSH / Remote Access | 17 |
| CMS / Web Admin Panel | 17 |
| Legacy / Backdoor Service | 16 |
| DNS / mDNS | 12 |
| Kernel / OS Privilege | 13 |
| Firewall / Network Policy | 11 |
| Application Server / Java | 12 |
| File Sharing | 11 |
| Library / Language Runtime | 11 |
| Free-roam (Hivestorm) | 16 |
| Mail / Messaging | 7 |
| FTP | 6 |
| CI/CD / DevOps | 3 |
| **Total** | **313** |

## Repository Layout

```
sysrepair-bench/
├── ccdc/                    # 50 CCDC-derived scenarios (scenario-01..50)
├── meta2/                   # 40 Metasploitable 2 / OpenVAS scenarios (scenario-01..40; S34-S40 = Compensating Controls)
├── vulnhub/                 # 30 VulnHub-derived scenarios (scenario-01..30)
├── meta3/ubuntu/            # 19 Metasploitable 3 (Ubuntu 14.04) scenarios + vendored Chef cookbook (shared/)
├── meta3/windows/           # 21 Metasploitable 3 (Windows Server) scenarios (harness validation)
├── meta4/                   # 137 modern-CVE scenarios (117 Docker + 20 AD-VM)
│   ├── kernel-vm/           #   Vagrant VM for kernel-coupled LPE scenarios (S19, S21, S22, S117)
│   └── ad-vm/               #   Vagrant AD lab (Win2019 DC+CA + Kali attacker, S01–S20)
├── hivestorm/               # 16 free-roam Hivestorm-style scenarios (weighted partial-credit)
├── openvas-scan-reports/    # OpenVAS scan PDFs scoping meta2 and meta3/windows
├── inspect_eval/            # Inspect AI harness: solvers, task wiring, run presets
└── README.md
```

Every scenario, across all three suites, follows the same layout at minimum:

```
scenario-NN/
├── Dockerfile   # Builds the vulnerable container
├── threat.md    # Severity, CVE, affected service, remediation steps
└── verify.sh    # exit 0 = remediated + functional, exit 1 = failed
```

## Remediation Action Space

Scenarios are scoped so that fixes are expressible as system-administration primitives:

| Action | Examples |
|--------|----------|
| `edit_file_parameter` | `sshd_config`, `nginx.conf`, `my.cnf`, `php.ini`, `pg_hba.conf` |
| `install_package` / `update_package` | `fail2ban`, `ufw`, `openssl`, `samba` |
| `remove_package` | `telnetd`, `rsh-server`, `nmap`, backdoors |
| `chmod` / `chown` | `/etc/shadow`, web roots, SUID binaries |
| `service_stop` / `service_disable` | `rlogin`, `avahi-daemon`, `cups` |
| `iptables_block` | Backdoor ports (1524, 1099, 6200, …) |

## Evaluation Criteria

Every scenario is scored on two mandatory objectives, plus — for Compensating-Controls scenarios — a third:

1. **Security objective (primary).** The specific vulnerability described in `threat.md` is eliminated. Verified by the scenario's `verify.sh` PoC block: a CVE is no longer exploitable, a misconfiguration is corrected, an insecure service is disabled or hardened, permissions are properly restrictive.
2. **Service availability (regression).** Every service that was operational before remediation stays operational afterward. A fix that patches the vulnerability but kills the web server, database, or SSH management path is scored as a failure. Verified by the scenario's `verify.sh` regression block.
3. **Compensating-control adequacy** *(Compensating Controls category only).* Where direct remediation is forbidden by the scenario constraints, `verify.sh` additionally asserts that the attack-surface reduction is in place (firewall rule present, listener scoped to loopback, WAF/`mod_rewrite` guard active, unsafe config directive removed).

A scenario is scored **success only if all applicable objectives pass**.

Scenarios may additionally track command count, wall-clock, safety violations (destructive commands outside remediation scope), hallucination (claimed actions that were not executed), and invariant preservation (prior hardening not undone while fixing the target).

## Out of Scope

SysRepair-Bench does **not** cover:

- **Source code modification.** The agent never edits application source, generates code patches, or runs application test suites. That is the domain of SWE-bench and automated program repair.
- **Web-application vulnerabilities requiring code fixes** (SQLi/XSS/CSRF). Web-server *configuration* hardening (directory listing, security headers, disabling unsafe modules) is in scope; changing application logic is not.
- **Cloud-native / Kubernetes-specific issues.** IAM policy, orchestration misconfig, and cloud-service settings are out of scope.
- **Zero-days with no known remediation.** Every scenario has at least one valid remediation path; the benchmark tests whether agents find and execute it.
- **Hardware / firmware vulnerabilities** (Spectre, Meltdown, etc.).

## Set-up

SysRepair-Bench builds every scenario from source. Depending on which suites you intend to run, you will need some or all of Docker, Vagrant + VirtualBox, Python (via `uv`), and a small set of platform-specific toggles. This section lists **everything** the repo needs to work correctly.

### 1. Clone the repo

```bash
# Anonymous repository URL (provided by reviewing system)
git clone <anonymous-repo-url>
cd sysrepair-bench
```

### 2. Core dependencies (all suites)

| Tool | Minimum | Purpose |
|---|---|---|
| `git` | 2.30+ | clone + submodule handling |
| Docker Engine / Docker Desktop | 24.x+ | builds and runs every container scenario |
| [`uv`](https://docs.astral.sh/uv/) | 0.4+ | Python env + lockfile for the Inspect AI harness |
| Python | 3.11+ (installed automatically by `uv sync`) | harness runtime |
| `bash` | 4+ | `prepare.sh`, `verify.sh`, seed scripts (Git Bash / WSL / macOS / Linux) |

Install the Inspect AI harness:

```bash
cd inspect_eval
uv sync              # creates .venv, installs Inspect AI + providers
cd ..
```

No other system-level Python packages are needed — everything the scenarios do runs inside containers or VMs.

### 3. Suite-specific host requirements

#### 3a. `ccdc/`, `vulnhub/`, `meta3/ubuntu/`, `meta4/` (container suites — any Docker host)

No extras beyond Docker. These use modern base images (Ubuntu 14.04 / 22.04, Debian 11 / 12, Alpine, vendor images). On first run, the harness will `docker build` each scenario on demand. Runtime-escape scenarios (Leaky Vessels, docker.sock, `--privileged` abuse) are auto-elevated by the harness when a `.needs-privileged` marker is present in the scenario dir — no manual `docker run --privileged` needed.

#### 3b. `meta2/` — Linux host only

> The Metasploitable 2 suite uses `lpenz/ubuntu-hardy-amd64` (Ubuntu 8.04). Hardy's glibc requires the legacy `vsyscall` page, which is disabled in the Docker Desktop / WSL2 kernels shipped on Windows and macOS. Every process SIGSEGVs (exit 139) before `apt-get` runs.

Requirements:
- A **native Linux host** (or a VM) with one of:
  - kernel booted with `vsyscall=emulate` (default on most distro kernels < 6.x; explicit on 6.x)
  - a WSL2 custom kernel rebuilt with `CONFIG_LEGACY_VSYSCALL_EMULATE=y` (advanced, not supported by Docker Desktop)

Pre-build the shared Hardy base (auto-built on first run, or manually):

```bash
docker build -t sysrepair/meta2-hardy:latest meta2/_base
```

The harness injects `cap_add=["NET_ADMIN"]` for every scenario and `privileged=True` where a `.needs-privileged` marker is present ([inspect_eval/sysrepair_bench/task.py:274-275](inspect_eval/sysrepair_bench/task.py#L274-L275)), so iptables-manipulating scenarios (`meta2/scenario-37`, `scenario-39`) and runtime-escape scenarios need no manual runtime flags when launched via `uv run python -m sysrepair_bench.run`.

#### 3c. Windows-container scenarios — Windows host only

> Windows containers (`mcr.microsoft.com/windows/servercore`) share the Windows NT kernel with the host; they cannot run on Linux or macOS. Meta4 has **no** Windows-container scenarios — only Linux images; its Windows host requirement is limited to `meta4/kernel-vm/` (see 3d).

Applies to:
- **All 20 `meta3/windows/` scenarios** (Server Core ltsc2019/ltsc2022)
- **Hivestorm Windows-container scenarios**: [`scenario-03-win10`](hivestorm/scenario-03-win10/), [`scenario-04-win2019`](hivestorm/scenario-04-win2019/), [`scenario-05-win2016`](hivestorm/scenario-05-win2016/) (ltsc2016 — note below), [`scenario-08-win-iis`](hivestorm/scenario-08-win-iis/), [`scenario-11-win-dc-dns`](hivestorm/scenario-11-win-dc-dns/)
- (Hivestorm `scenario-13-ad-dc-win2019` is VM-based, not container-based — see 3e)

Requirements:
- Windows 10/11 **Pro/Enterprise** or Windows Server 2019+ (Home editions lack Containers + Hyper-V isolation)
- Docker Desktop switched to **Windows Containers** mode (tray-icon → "Switch to Windows containers"), **or** a native Windows `dockerd`
- Hyper-V + Containers features (elevated PowerShell):

  ```powershell
  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
  Enable-WindowsOptionalFeature -Online -FeatureName Containers -All
  ```

- Internet access for `docker build` to pull `mcr.microsoft.com/windows/servercore:ltsc201{6,9}` and the pinned legacy installers on first build (or an offline mirror for air-gapped builds)

**Isolation mode.** The harness auto-injects `isolation: hyperv` for every Windows-container scenario ([task.py:22-30](inspect_eval/sysrepair_bench/task.py#L22-L30), [task.py:275](inspect_eval/sysrepair_bench/task.py#L275)), so mismatched builds like `ltsc2016` (hivestorm `scenario-05-win2016`) run correctly on any supported Windows host. For manual `docker run` outside the harness, enable Hyper-V isolation one of two ways:

- **Docker Desktop (GUI):** Settings → General → enable "Use the WSL 2 based engine" is **not** what you want for Windows containers — instead right-click the tray icon → *Switch to Windows containers*, then in Settings → General toggle *Use Hyper-V isolation by default* (wording varies by version), Apply & Restart.
- **Native `dockerd` / daemon config:** add `"exec-opts": ["isolation=hyperv"]` to `%ProgramData%\docker\config\daemon.json` and restart the Docker service.

Per-scenario isolation recommendations for manual runs are in [`meta3/windows/README.md`](meta3/windows/README.md).

#### 3d. `meta4/kernel-vm/` — VirtualBox VM for kernel-coupled LPE scenarios (S21, S22, S117; optionally S19)

> These scenarios target kernel vulnerabilities. Containers share the host kernel, so they need a VM whose kernel matches the vulnerable ABI range. S19 (Dirty Pipe) additionally requires a separate Ubuntu 20.04 HWE host — or remediate in **compensating-control mode** (`chattr +i`) on any host. S117 (Copy Fail, CVE-2026-31431) runs on the existing VM's pinned 5.15 kernel (no backport exists) — or remediate by blacklisting `algif_aead`.

Requirements:
- **BIOS/UEFI**: Intel VT-x / AMD-V enabled (optionally VT-d / AMD-Vi)
- **Windows hosts**: Hyper-V stack disabled so VirtualBox can claim VT-x:

  ```powershell
  dism.exe /Online /Disable-Feature:Microsoft-Hyper-V-All /NoRestart
  dism.exe /Online /Disable-Feature:VirtualMachinePlatform /NoRestart
  dism.exe /Online /Disable-Feature:HypervisorPlatform /NoRestart
  dism.exe /Online /Disable-Feature:Containers /NoRestart
  bcdedit /set hypervisorlaunchtype off
  ```

  Also: **Windows Security → Device security → Core isolation → Memory Integrity OFF**, then reboot.

- **VirtualBox 7.x** and **Vagrant 2.4.x**:

  Windows (via [Scoop](https://scoop.sh)):
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  irm get.scoop.sh | iex
  scoop install git vagrant
  scoop bucket add extras
  scoop install virtualbox
  ```

  Ubuntu / Debian:
  ```bash
  sudo apt install -y virtualbox vagrant
  sudo usermod -aG vboxusers "$USER"   # log out / back in afterwards
  ```

- Bring up the VM:

  ```bash
  cd meta4/kernel-vm
  vagrant up        # Ubuntu 22.04, kernel pinned pre-fix, Docker installed
  vagrant ssh
  ```

Note: kernel-scenarios inside the VM require `docker run --privileged` to exercise the host kernel's userns behavior.

#### 3e. `hivestorm/` — free-roam scenarios

Container scenarios (01, 02, 06, 07, 09, 10, 12, 15, 16) run on any Docker host. Windows scenarios (03, 04, 05, 08, 11) require the same host as [`meta3/windows/`](#3c-meta3windows--windows-host-only).

Before every run, regenerate randomized identities (backdoor account, trojan path, SUID plant, rogue cron, legit admin name):

```bash
bash hivestorm/prepare.sh            # all scenarios, random seed
SEED=42 bash hivestorm/prepare.sh    # reproducible
bash hivestorm/prepare.sh 01         # single scenario
```

`scenario-15-docker-host` (dockerd-in-container) is auto-elevated by the harness via its `.needs-privileged` marker.

##### VM-backed hivestorm scenarios (13, 14)

These use Vagrant; AD-DC and FreeBSD cannot run inside containers.

| Scenario | Box | Provider | Extras |
|---|---|---|---|
| `scenario-13-ad-dc-win2019` | `gusztavvargadr/windows-server-2019-standard` | VirtualBox (default) or Hyper-V | Vagrant ≥ 2.3, VirtualBox ≥ 6.1; first boot ~15 min (ADDS promote + reboot + seed) |
| `scenario-14-freebsd13` | `freebsd/FreeBSD-13.2-RELEASE` | VirtualBox (default) or libvirt | Vagrant ≥ 2.3, VirtualBox ≥ 6.1; first boot ~5–8 min |

```bash
bash hivestorm/prepare.sh 13
cd hivestorm/scenario-13-ad-dc-win2019
vagrant up
```

### 4. Model provider credentials (for running agents)

The Inspect AI harness needs at least one provider. Set the env vars for whichever you use:

| Provider | Env var |
|---|---|
| OpenAI / OpenAI-compatible (vLLM, Ollama via `OPENAI_BASE_URL`) | `OPENAI_API_KEY`, optionally `OPENAI_BASE_URL` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Google (Gemini) | `GOOGLE_API_KEY` |
| Hugging Face Inference | `HF_TOKEN` |

For local inference, point `OPENAI_BASE_URL` at a vLLM / Ollama / LM Studio endpoint and set `OPENAI_API_KEY` to any non-empty string.

### 5. Quick verification

```bash
# Sanity: build + verify a single container scenario
cd vulnhub/scenario-01
docker build -t sysrepair-vulnhub-01 .
docker run -d --name test-01 sysrepair-vulnhub-01
docker exec test-01 /bin/bash /verify.sh
echo $?          # 1 = baseline still vulnerable (expected before remediation)
docker rm -f test-01

# Sanity: harness smoke test (one scenario, ReAct solver)
cd ../../inspect_eval
uv run python -m sysrepair_bench.run smoke
```

## Using SysRepair-Bench

### Build and run a single scenario

```bash
cd vulnhub/scenario-01
docker build -t sysrepair-vulnhub-01 .
docker run -d --name test-01 sysrepair-vulnhub-01
```

### Have the agent perform remediation

Drop the agent into the container (or let it operate via its own tools):

```bash
docker exec -it test-01 /bin/bash
# ... agent makes configuration, package, or permission changes ...
```

### Verify remediation

```bash
docker exec test-01 /bin/bash /verify.sh
echo $?   # 0 = remediated and service still works, 1 = failed
```

## Prompt / Scenario Metadata

Each `threat.md` is written as a self-contained prompt and provides:

- **Severity** and CVSS score
- **CVE** (where applicable)
- **Affected service** (binary, port, config path)
- **Vulnerable configuration** snippet
- **Remediation steps**

Agents should be evaluated under either a *zero-knowledge* variant (only the container is exposed) or a *one-day* variant (threat.md is provided as context). The `verify.sh` grader is the same in both cases.

## Running agents with the Inspect AI harness

An end-to-end evaluation harness built on [Inspect AI](https://inspect.aisi.org.uk/) lives in [`inspect_eval/`](inspect_eval/). It loads scenarios from every suite, runs an agent solver against each one in a Docker sandbox, invokes `verify.sh`, and records pass/fail plus trajectory telemetry.

### Quickstart

```bash
cd inspect_eval
uv sync

# Single scenario smoke test
uv run python -m sysrepair_bench.run smoke

# Full meta2 suite, ReAct solver, local Ollama
uv run python -m sysrepair_bench.run meta2_react_local
```

### Available presets

Presets are declared in [`inspect_eval/runs.yaml`](inspect_eval/runs.yaml). Each preset pins a model, solver, benchmark selection, and timeouts.

| Preset | Purpose |
|---|---|
| `smoke` | One-scenario sanity check (`meta2/scenario-01`, ReAct) |
| `meta2_react_local` | Full `meta2/` suite under ReAct, local model |
| `meta2_lats_local` | Full `meta2/` suite under LATS tree search |
| `pas_gpt` | Plan-and-Solve on `meta2/` |
| `full_reflexion_qwen` | Reflexion across `meta2`, `vulnhub`, `ccdc` |
| `full_matrix` | 10 open-weight models × 5 solvers × 3 benchmarks (HPC) |

### Solvers

`react`, `basic`, `reflexion`, `plan_and_solve`, `lats` — all exposed via the `solver:` key in a preset.

### Timeouts & safety

Defaults in `runs.yaml`: `time_limit=1800s`, `token_limit=500k`, `bash_timeout=180s`, `verify_timeout=300s`. Every `bash` and `verify.sh` invocation has an explicit timeout so a hung service can't stall the run; LATS marks timed-out nodes as fatal rather than re-expanding them. The tool surface is bash-only (no Python) because Metasploitable-2-era containers may not ship a Python interpreter.

See [`inspect_eval/README.md`](inspect_eval/README.md) for the full list of task parameters, scoring fields, and harness internals.

## Citation

Author and citation information are withheld for double-blind review.

## Acknowledgements

Scenarios draw on public material from:
- Collegiate Cyber Defense Competition (CCDC) team hardening toolkits — TAMU linuxmonkeys, LATech 2023 SWCCDC, UTSA 2023 SWCCDC
- OpenVAS scan of [Metasploitable 2.0](https://information.rapid7.com/download-metasploitable-2017.html)
- [VulnHub](https://www.vulnhub.com/) community VMs (Kioptrix, DC-series, Mr-Robot, SickOs, Symfonos, FristiLeaks, LinSecurity, Brainpan, De-ICE, PwnOS)
- Rapid7 [metasploitable3](https://github.com/rapid7/metasploitable3) — `meta3/ubuntu/shared/cookbooks/` vendors portions of the upstream Chef cookbook (BSD-3-Clause, © Rapid7, Inc.) to provision the Meta3-Ubuntu software stack (Drupal, payroll_app, phpMyAdmin, ProFTPD, UnrealIRCd, Samba). Full attribution in [`meta3/ubuntu/shared/UPSTREAM_LICENSE`](meta3/ubuntu/shared/UPSTREAM_LICENSE). The Windows sub-suite will similarly reference the upstream Packer/Vagrant installer scripts once authored.
- [OpenVAS / Greenbone](https://www.greenbone.net/) for the scan reports in [`openvas-scan-reports/`](openvas-scan-reports/) that drive the meta2 and meta3 scenario scopes
