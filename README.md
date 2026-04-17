# SysRepair-Bench: A Benchmark for AI Agents' Ability to Remediate Real-World System Vulnerabilities

## Overview

SysRepair-Bench evaluates autonomous agents on their ability to **remediate** misconfigurations, vulnerable dependencies, unsafe permissions on real systems. Each scenario is a reproducible Docker container/ Virtual Machine seeded with a known-vulnerable state drawn from public red-team material (CCDC hardening checklists, the Metasploitable 2 OpenVAS report, VulnHub VM write-ups, the Metasploitable 3 OpenVAS report, Hivestorm, Newly Designed Metasploitable 4 VM).

For each scenario, given only the running container and Optional(threat description), an agent must perform system-administration actions (edit configuration, install/remove packages, adjust permissions, manage services, etc.) until:

1. **PoC check** — the original vulnerability is no longer exploitable, AND
2. **Regression check** — the affected service still functions correctly.

Remediation is scored as successful **only if both checks pass**.

The benchmark comprises **285 scenarios across five VM classes** (six suites): `ccdc/` (50), `meta2/` (40), `vulnhub/` (30), `meta3/ubuntu/` (19), `meta3/windows/` (20), and `meta4/` (109) — plus a **16-scenario `hivestorm/` free-roam track** that ships alongside the binary-pass/fail suites and uses weighted partial-credit scoring.

| VM Class / Suite | Era | Built | Source |
|---|---|---|---|
| [`ccdc/`](ccdc/) | 2015–2022 | 50 | CCDC blue-team hardening scripts (TAMU linuxmonkeys, LATech/UTSA SWCCDC, team checklists) on Ubuntu 25.10 |
| [`meta2/`](meta2/) | 2008–2012 | 40 | OpenVAS scan of Metasploitable 2.0 on Ubuntu 8.04. ⚠ **Linux host only** (see Host Requirements) |
| [`vulnhub/`](vulnhub/) | 2012–2022 | 30 | Per-VM vulnerability rebuilds (Kioptrix, DC-series, Mr-Robot, SickOs, Symfonos, etc.) on Debian 11 |
| [`meta3/ubuntu/`](meta3/ubuntu/) | 2014–2020 | 19 | Port of Rapid7 Metasploitable 3 (Ubuntu 14.04) — Drupalgeddon, ProFTPD mod_copy, payroll_app, Docker group escalation, WEBrick, UnrealIRCd, Samba, phpMyAdmin. Vendors the Rapid7 Chef cookbook under BSD-3. |
| [`meta3/windows/`](meta3/windows/)| 2016–2020 | 20 | Rapid7 Metasploitable 3 (Windows Server) — Struts, Jenkins, ManageEngine, GlassFish, Tomcat, ElasticSearch, IIS WebDAV, SMB. Scoped by the [Windows OpenVAS scan](openvas-scan-reports/metasploitable-3.0-win-openvas.pdf). ⚠ **Windows host only** (see Host Requirements) |
| **[`meta4/`](meta4/)** | 2022–2026 | 109 | Container suite covering modern CVEs (Log4Shell family, Spring4Shell, PwnKit, Dirty Pipe, GameOver(lay), regreSSHion, Leaky Vessels, XZ backdoor, crAPI/DVGA/VAmPI API surfaces, LocalStack/MinIO/ArgoCD/k3s cloud-on-localhost misconfigs, ImageMagick, Memcached, curl SOCKS5, Redis Lua sandbox, Adminer, Apache Solr, Rsync, Cacti, and more) that fill the temporal gap left by aging Metasploitable and VulnHub images. Kernel-coupled scenarios ship a Vagrant VM ([`meta4/kernel-vm/`](meta4/kernel-vm/)). |
| [`hivestorm/`](hivestorm/) | HS20–HS23 | 16 | **Free-roam** Hivestorm-style scenarios (Debian/Ubuntu/CentOS/Windows Server-Core/FreeBSD/AD-DC). Identities (backdoor account, trojan path, rogue cron, SUID plant) are randomized per build; the scorer emits weighted partial credit via JSONL checks rather than binary pass/fail. |

### Vulnerability categories

Every scenario's **(expect hivestorm)** `threat.md` is labeled with one of **five operational remediation categories** that mirror how security-operations teams classify remediation work:

1. **Access Control** — authentication, authorization, user privileges, file ownership. Typical actions: `chmod`, `chown`, `usermod`, `passwd`, `visudo`, `sshd_config`, PAM.
2. **Configuration Hardening** — insecure defaults, missing security directives, misconfigured service parameters. Typical actions: edits to `nginx.conf`, `sshd_config`, `my.cnf`, `apache2.conf`, `pg_hba.conf`, followed by `systemctl reload`/`restart`.
3. **Dependency & Package Management** — outdated packages with known CVEs, inherently compromised services, unnecessary high-risk daemons. Typical actions: `apt-get upgrade`, `--only-upgrade`, `remove`, `systemctl disable`.
4. **Network Security & Firewall Policy** — exposed ports, missing firewall rules, unrestricted listener scope. Typical actions: `ufw`, `iptables`, bind-address changes, TCP wrappers, `netstat`/`ss` auditing.
5. **Compensating Controls**, This covers vulnerabilities where direct remediation is not possible or not desirable — the package cannot be upgraded because a dependent legacy app requires the specific version, the software is end-of-life with no vendor patch, or the service cannot be restarted during business hours. The agent must instead apply network-level restrictions (firewall scoping, bind-to-localhost), application-layer mitigations (WAF rules, `mod_rewrite` guards, ACLs), or safe config-directive removals while keeping the service usable. Scoring adds a third dimension: **compensating-control adequacy** — whether the applied controls meaningfully reduce the attack surface.

### Severity distribution

Distribution of base severity scores across all 285 scenarios. Scores follow CVSS v3.1; scenarios without a CVE (CCDC misconfigs, Hivestorm free-roam) are unscored.

| Severity | CVSS v3.1 Range | # Scenarios |
|---|---|---|
| Critical | 9.0–10.0 | 88 |
| High | 7.0–8.9 | 84 |
| Medium | 4.0–6.9 | 39 |
| Low | 0.1–3.9 | 1 |
| Unscored (misconfig / free-roam) | — | 73 |
| **Total** | | **285** |

### Remediation category distribution

| Remediation Category | # Scenarios |
|---|---|
| Configuration Hardening | 101 |
| Dependency & Package Management | 52 |
| Access Control | 51 |
| Compensating Controls | 47 |
| Network Security | 18 |
| Free-roam (multiple) | 16 |
| **Total** | **285** |

### Service / application type distribution

| Service / Application Type | # Scenarios |
|---|---|
| Web Server | 60 |
| Enterprise / Infrastructure | 26 |
| System / Auth | 21 |
| Container / Runtime | 19 |
| Database / Cache | 18 |
| SSH / Remote Access | 17 |
| CMS / Web Admin Panel | 17 |
| Legacy / Backdoor Service | 16 |
| DNS / mDNS | 12 |
| Kernel / OS Privilege | 12 |
| Firewall / Network Policy | 11 |
| Application Server / Java | 11 |
| File Sharing | 10 |
| Library / Language Runtime | 10 |
| Free-roam (Hivestorm) | 9 |
| Mail / Messaging | 7 |
| FTP | 6 |
| CI/CD / DevOps | 3 |
| **Total** | **285** |

## Repository Layout

```
sysrepair-bench/
├── ccdc/                    # 50 CCDC-derived scenarios (scenario-01..50)
├── meta2/                   # 40 Metasploitable 2 / OpenVAS scenarios (scenario-01..40; S34-S40 = Compensating Controls)
├── vulnhub/                 # 30 VulnHub-derived scenarios (scenario-01..30)
├── meta3/ubuntu/            # 19 Metasploitable 3 (Ubuntu 14.04) scenarios + vendored Chef cookbook (shared/)
├── meta3/windows/           # 20 Metasploitable 3 (Windows Server) scenarios (harness validation)
├── meta4/                   # 109 modern-CVE container scenarios
│   └── kernel-vm/           #   Vagrant VM for kernel-coupled LPE scenarios (S21, S22)
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

SysRepair-Bench uses Docker, Packer and Vargrant for reproducibility and isolation. Install Docker, Packer, Vargrant and uv

```bash
git clone https://github.com/BaylorSecurityLab/sysrepair-bench.git
cd sysrepair-bench
```

No additional Python dependencies are required to build and verify a scenario — everything runs inside the container.

### Host requirements for the `meta2/` suite

> ⚠ **The `meta2/` suite runs on a native Linux host only.** It cannot be executed
> under Docker Desktop on Windows or macOS, and will not work under the default
> WSL2 kernel. The `ccdc/` and `vulnhub/` suites use modern base images and run
> on any Docker host.

The Metasploitable 2 suite uses the `lpenz/ubuntu-hardy-amd64` base image (Ubuntu 8.04).
Ubuntu 8.04's glibc relies on the legacy `vsyscall` page, which was removed from the
upstream Linux kernel in 5.18 and is **disabled by default in the Docker Desktop /
WSL2 kernel on Windows and macOS**. On such hosts every process in a Hardy container
exits with SIGSEGV (exit 139) before `apt-get` even starts.

Run the `meta2/` scenarios on a native Linux host with one of:

- A kernel booted with the `vsyscall=emulate` boot parameter (the default on most
  distro kernels <6.0; explicit on 6.x).
- A WSL2 custom kernel rebuilt with `CONFIG_LEGACY_VSYSCALL_EMULATE=y` (advanced;
  not a supported Docker Desktop configuration).

Scenarios `meta2/scenario-37` and `meta2/scenario-39` manipulate `iptables` and must
be run with `--cap-add=NET_ADMIN`:

```bash
docker run -d --cap-add=NET_ADMIN --name meta2-s39 meta2-s39
```

### Host requirements for the `meta3/windows/` sub-suite

> ⚠ **The `meta3/windows/` sub-suite runs on a Windows host only.** It cannot be
> executed on Linux or macOS — Windows containers (`mcr.microsoft.com/windows/servercore`)
> share the Windows NT kernel with the host and have no Linux equivalent. The
> `meta3/ubuntu/` sub-suite, `ccdc/`, and `vulnhub/` all run on any Docker host.

The Windows sub-suite requires:

- Windows 10/11 **Pro or Enterprise**, or Windows Server 2019+ (Home editions do not support Windows Containers or Hyper-V isolation)
- Docker Desktop switched to **Windows Containers** mode (right-click the tray icon → "Switch to Windows containers"), **or** a native Windows `dockerd` install
- Hyper-V and Containers features enabled: `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All` and `Enable-WindowsOptionalFeature -Online -FeatureName Containers -All`
- ~40 GB free disk for the Server Core base image plus per-scenario layers

Process isolation works when the container's Windows build matches the host; Hyper-V isolation (`--isolation=hyperv`) is the safe default for mixed builds. See [`meta3/windows/README.md`](meta3/windows/README.md) for per-scenario isolation requirements.

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

## Suites

| | [ccdc/](ccdc/README.md) | [meta2/](meta2/README.md) | [vulnhub/](vulnhub/README.md) | [meta3/](meta3/README.md) | [meta4/](meta4/README.md) |
|---|---|---|---|---|---|
| Base image | `ubuntu:25.10` | `lpenz/ubuntu-hardy-amd64` (Ubuntu 8.04 — **Linux host only; requires `vsyscall=emulate` kernel**) | `debian:11` (+ 2 pinned pulled images) | `ubuntu:14.04` ([`meta3/ubuntu/`](meta3/ubuntu/README.md)) + `mcr.microsoft.com/windows/servercore` ([`meta3/windows/`](meta3/windows/README.md), Windows host required) | Mixed: vendor-pinned vulnerable images (`tomcat:9.0.60-jdk11`, `httpd:2.4.49/50`, `atlassian/confluence-server:7.18.0`, `gitlab/gitlab-ce:16.7.0`), `ubuntu:22.04` / `debian:testing-20240301` for userspace LPE & XZ, `docker:24-dind` for runtime escapes, plus a kernel-pinned Vagrant VM for S21/S22 |
| Scenarios | 50 | 40 | 30 | 19 Ubuntu / 20 Windows | 109 |
| Categories | Config (1–25), Dependencies (26–38), Permissions (39–50) | Config (1–15), Patch-mgmt (16–24), Access-control (25–29), Network-exposure (30–33), **Compensating Controls (34–40)** | Per-VM vulnerabilities across 14 VulnHub VMs | Ubuntu: Config (S01–S05, S18, S19), Patch (S06–S09), Access (S10, S11), Network (S12), **Compensating** (S13–S17). Windows sub-suite same shape, scoped by the [Windows OpenVAS scan](openvas-scan-reports/metasploitable-3.0-win-openvas.pdf). | All five remediation categories across 109 scenarios: Access Control, Config Hardening, Dependency/Patch, Network Security, plus kernel LPE (S19/S21/S22), container/runtime escape (Leaky Vessels, docker.sock, `--privileged`), and miscellaneous CVEs (ImageMagick, Memcached, curl, Redis, Solr, Rsync, Cacti) |

Alongside these five binary-pass/fail suites, [`hivestorm/`](hivestorm/README.md) ships 16 **free-roam** scenarios (Debian/Ubuntu/CentOS/Windows Server-Core/FreeBSD/AD-DC) with per-build identity randomization and a weighted partial-credit scorer. It uses the same Inspect AI harness; selection is via `benchmark: hivestorm` in `runs.yaml`.

See each suite's README for the full scenario index.

## Citation

If you use SysRepair-Bench in your work, please cite:

```
@misc{sysrepairbench,
  title  = {SysRepair-Bench: A Benchmark for Autonomous Remediation of Real-World System Vulnerabilities},
  author = {Orojo, Abanisenioluwa Kolawole and Elumelu, Webster and El-Mahmoud, Emmanuelli and Leal, Erika and Rivas, Pablo},
  year   = {2026},
}
```

## Acknowledgements

Scenarios draw on public material from:
- Collegiate Cyber Defense Competition (CCDC) team hardening toolkits — TAMU linuxmonkeys, LATech 2023 SWCCDC, UTSA 2023 SWCCDC
- OpenVAS scan of [Metasploitable 2.0](https://information.rapid7.com/download-metasploitable-2017.html)
- [VulnHub](https://www.vulnhub.com/) community VMs (Kioptrix, DC-series, Mr-Robot, SickOs, Symfonos, FristiLeaks, LinSecurity, Brainpan, De-ICE, PwnOS)
- Rapid7 [metasploitable3](https://github.com/rapid7/metasploitable3) — `meta3/ubuntu/shared/cookbooks/` vendors portions of the upstream Chef cookbook (BSD-3-Clause, © Rapid7, Inc.) to provision the Meta3-Ubuntu software stack (Drupal, payroll_app, phpMyAdmin, ProFTPD, UnrealIRCd, Samba). Full attribution in [`meta3/ubuntu/shared/UPSTREAM_LICENSE`](meta3/ubuntu/shared/UPSTREAM_LICENSE). The Windows sub-suite will similarly reference the upstream Packer/Vagrant installer scripts once authored.
- [OpenVAS / Greenbone](https://www.greenbone.net/) for the scan reports in [`openvas-scan-reports/`](openvas-scan-reports/) that drive the meta2 and meta3 scenario scopes
