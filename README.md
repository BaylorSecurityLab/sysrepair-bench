# SysRepair-Bench: A Benchmark for AI Agents' Ability to Remediate Real-World System Vulnerabilities

## Overview

SysRepair-Bench evaluates autonomous agents on their ability to **remediate** misconfigurations, vulnerable dependencies, and unsafe permissions on real Linux systems. Each scenario is a reproducible Docker container seeded with a known-vulnerable state drawn from public red-team material (CCDC hardening checklists, the Metasploitable 2 OpenVAS report, and VulnHub VM write-ups).

For each scenario, given only the running container and a threat description, an agent must perform system-administration actions (edit configuration, install/remove packages, adjust permissions, manage services, etc.) until:

1. **PoC check** — the original vulnerability is no longer exploitable, AND
2. **Regression check** — the affected service still functions correctly.

Remediation is scored as successful **only if both checks pass**.

The benchmark currently contains **113 scenarios** across three suites:

| Suite | Scenarios | Source | Focus |
|-------|-----------|--------|-------|
| [`ccdc/`](ccdc/) | 50 | CCDC hardening scripts (TAMU linuxmonkeys, LATech/UTSA SWCCDC, team checklists) | Configuration, dependencies, permissions on Ubuntu 25.10 |
| [`meta2/`](meta2/) | 33 | OpenVAS scan of Metasploitable 2.0 | Legacy services and CVEs on Ubuntu 8.04 |
| [`vulnhub/`](vulnhub/) | 30 | VulnHub VM vulnerability analysis (Kioptrix, DC-series, Mr-Robot, SickOs, Symfonos, etc.) | Per-VM vulnerabilities rebuilt on Debian 11 or pulled images |

## Repository Layout

```
sysrepair-bench/
├── ccdc/                    # 50 CCDC-derived scenarios (scenario-01..50)
├── meta2/                   # 33 Metasploitable 2 / OpenVAS scenarios (scenario-01..33)
├── vulnhub/                 # 30 VulnHub-derived scenarios (scenario-01..30)
└── README.md
```

Every scenario, across all three suites, follows the same layout:

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

Scenarios requiring source-code patches (XSS/SQLi in web apps, language-runtime bugs) are **out of scope** — those belong to code-repair benchmarks.

## Set-up

SysRepair-Bench uses Docker for reproducibility and isolation. Install Docker via the [official guide](https://docs.docker.com/engine/install/).

```bash
git clone https://github.com/<org>/sysrepair-bench.git
cd sysrepair-bench
```

No additional Python dependencies are required to build and verify a scenario — everything runs inside the container.

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

## Suites

| | [ccdc/](ccdc/README.md) | [meta2/](meta2/README.md) | [vulnhub/](vulnhub/README.md) |
|---|---|---|---|
| Base image | `ubuntu:25.10` | `navig/ubuntu:8.04` | `debian:11` (+ 2 pinned pulled images) |
| Scenarios | 50 | 33 | 30 |
| Categories | Config (1–25), Dependencies (26–38), Permissions (39–50) | Config, Patch-mgmt, Access-control, Network-exposure | Per-VM vulnerabilities across 14 VulnHub VMs |

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
