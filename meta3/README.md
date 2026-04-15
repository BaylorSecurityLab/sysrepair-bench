# SysRepair-Bench: Metasploitable 3 Extension

## Overview

This directory contains the **Metasploitable 3** suite, split into two OS-specific sub-suites that share a common scenario format:

- [`ubuntu/`](ubuntu/README.md) — Linux targets derived from **Metasploitable 3 (Ubuntu 14.04)**. Scope is picked from the OpenVAS scan in [`../openvas-scan-reports/metasploitable-3.0-ubu-openvas.pdf`](../openvas-scan-reports/metasploitable-3.0-ubu-openvas.pdf) plus the known Meta3-Ubuntu design surface (Drupal, ProFTPD, payroll app, credential reuse, etc.).
- [`windows/`](windows/README.md) — Windows targets derived from **Metasploitable 3 (Windows Server 2008 R2)**. Scope is ported from the [Rapid7 metasploitable3 Packer/Vagrant build scripts](https://github.com/rapid7/metasploitable3). Scan-driven scenario list will be finalized once the Windows OpenVAS scan is committed.

Both sub-suites follow the SysRepair-Bench scenario format used by `meta2/`, `ccdc/`, and `vulnhub/`:

```
scenario-NN/
├── Dockerfile    # vulnerable target, reproducible build
├── threat.md     # severity, CVE, config, remediation steps
└── verify.sh     # dual check: PoC (vuln gone) + regression (service still usable)
```

Every scenario — including the patch-management ones and the compensating-control ones — **must keep its primary service reachable on its documented port after remediation**. A fix that patches the CVE but breaks the service counts as a regression failure.

## Why split by OS

Metasploitable 3 ships two distinct target images (Ubuntu 14.04 and Windows Server 2008 R2) with non-overlapping vulnerability surfaces, toolchains, and remediation primitives:

| | Ubuntu | Windows |
|---|---|---|
| Container base | `ubuntu:14.04` (with legacy repo pins) | `mcr.microsoft.com/windows/servercore:ltsc2019` (process-isolated) or `:ltsc2022` |
| Build style | `Dockerfile` + `apt-get` + config edits | `Dockerfile` + `powershell -Command` + silent installers |
| Host requirement | any Docker host | Windows Docker host with Windows Containers mode (or Hyper-V isolation) |
| Agent connectivity | `-p 2222:22` loopback port-forward, agent SSH | same pattern — each container gets a unique `localhost:<port>` mapping |

Keeping them in sibling folders lets the benchmark runner pick targets per OS without conditionally skipping half the suite.

## Host Requirements

### Ubuntu sub-suite
Standard Docker host. No kernel tricks required — unlike `meta2/` (which needs `vsyscall=emulate` for Hardy glibc), `meta3/ubuntu/` images boot on any modern kernel.

### Windows sub-suite
- Windows 10/11 Pro/Enterprise or Windows Server 2019+ as the Docker host
- Docker Desktop switched to **Windows Containers** mode (right-click tray → "Switch to Windows containers"), **or** a native Windows `dockerd` install
- For legacy 32-bit installers, use Server Core (not Nano Server) as the base image
- Hyper-V isolation is available but not required for most scenarios; process isolation works as long as the base image Windows build matches the host
- The agent runs on the same host and reaches each container via `localhost:<mapped-port>` — no transparent/bridge networking needed

## Agent connectivity model

The benchmark runs **sequentially**: one target container at a time, mapped to a fixed set of host ports. The agent connects to `localhost:<port>` and performs remediation in-place (SSH for Ubuntu, WinRM/SSH for Windows). When the scenario is done, the container is stopped and the next one starts, reusing the same host ports.

This keeps the benchmark portable — it runs on a laptop, a cloud VM, or a CI runner without needing promiscuous-mode NICs or DHCP-level network surgery. Parallel execution is possible for users who want to run multiple agents at once; they just assign a unique port block per container.

## Status

| Sub-suite | Scan source | Scenario count | State |
|---|---|---|---|
| [`ubuntu/`](ubuntu/README.md) | OpenVAS scan (Apr 2026) committed | 19 live | Dockerfiles, threat.md, verify.sh, Chef run-lists all stamped; vendored Rapid7 cookbook under [`ubuntu/shared/`](ubuntu/shared/README.md) |
| [`windows/`](windows/README.md) | OpenVAS scan pending | ~20 planned (from Rapid7 build scripts) | awaiting scan upload before scenarios are authored |

See each sub-suite's README for the full scenario index and build/run instructions.
