# meta4/ad-vm — Active Directory VM harness

Vagrant-provisioned Windows Server 2019 DC + Enterprise CA + Kali attacker,
hosting 20 Active-Directory-targeted SysRepair-Bench scenarios that cannot
run in Linux containers (Netlogon, Kerberos, LDAP, ADCS, Spooler, etc.).

Design rationale in `docs/superpowers/specs/2026-04-20-meta4-ad-vm-design.md`.

## Why a VM

AD attacks target real Windows domain services. Containers share the host
kernel, cannot host a DC, and cannot exercise MS-NRPC / Kerberos /
MS-LSAD / MS-CRTD the way the real protocols require. This mirrors the
precedent set by [`../kernel-vm/`](../kernel-vm/) for kernel-coupled
Linux LPEs.

## Prerequisites

- VirtualBox ≥ 7.0
- Vagrant ≥ 2.4.9 with the `vagrant-reload` plugin
  (`vagrant plugin install vagrant-reload`)
- `jq` on the host (used by `run-scenario.sh`)
- ~8 GB free RAM, ~40 GB free disk for three linked-clone VMs
- The community box `jborean93/WindowsServer2019` (pulled automatically
  on first `vagrant up`; a reproducible Packer template is on the
  roadmap for later phases)

## Quick start

```bash
cd meta4/ad-vm

vagrant plugin install vagrant-reload   # first time only
vagrant up                              # ~20 min on a cold host
./capture-baselines.sh                  # one-time snapshot capture

./run-scenario.sh 13                    # restore + inject S13
ssh vagrant@10.20.30.10                 # (password: vagrant)
#   ~/threat.md  ~/creds.txt  ~/tools/ → /opt/ad-tools/bin

# When the agent signals done:
./run-scenario.sh 13 --verify-only      # exits 0 iff both checks pass
```

## VMs

| Role | VM name | IP | Notes |
|---|---|---|---|
| DC / forest root | `corp-dc01` | `10.20.30.5` | `corp.local` / `CORP` NetBIOS |
| Enterprise CA | `corp-ca01` | `10.20.30.6` | Member of corp.local, ADCS EnterpriseRootCA |
| Kali attacker | `kali-attacker` | `10.20.30.10` | `corp\alice:Password1!` seeded in `~/creds.txt` |

## Scenario matrix

Phase 0 ships one smoke-test scenario. Phase 1–4 plans land the rest.

| # | Title | Category | Severity | CVE | Comp-ctrl |
|---|---|---|---|---|---|
| 01 | Zerologon | Access Control | Critical | CVE-2020-1472 | No |
| 02 | NoPac (sAMAccountName spoofing) | Access Control | Critical | CVE-2021-42278 / 42287 | No |
| 03 | Kerberoasting | Access Control | High | n/a | Yes |
| 04 | AS-REP roasting | Access Control | High | n/a | Yes |
| 05 | Unconstrained delegation | Access Control | High | n/a | Yes |
| 06 | DCSync rights to non-admin | Access Control | Critical | n/a | No |
| 07 | ADCS ESC1 | Configuration Hardening | Critical | n/a | Yes |
| 08 | ADCS ESC2 | Configuration Hardening | Critical | n/a | Yes |
| 09 | ADCS ESC3 | Configuration Hardening | High | n/a | Yes |
| 10 | ADCS ESC6 | Configuration Hardening | Critical | n/a | No |
| 11 | ADCS ESC8 | Configuration Hardening | Critical | n/a | Yes |
| 12 | LDAP signing not required | Compensating Controls | High | n/a | Yes |
| **13** | **SMB signing disabled (smoke test)** | **Compensating Controls** | **High** | **n/a** | **Yes** |
| 14 | NTLMv1 allowed | Compensating Controls | High | n/a | Yes |
| 15 | LLMNR / NBT-NS enabled | Network Security | Medium | n/a | Yes |
| 16 | PrintNightmare | Dependency Management | Critical | CVE-2021-34527 | Yes |
| 17 | PetitPotam (MS-EFSR) | Configuration Hardening | High | CVE-2021-36942 | Yes |
| 18 | GPP cpassword in SYSVOL | Access Control | High | n/a | No |
| 19 | LAPS not enforced | Access Control | Medium | n/a | Yes |
| 20 | AdminSDHolder backdoor ACL | Access Control | Critical | n/a | No |

## Scoring rubric

A scenario **passes** iff both:

1. `verify-poc.sh` on the attacker exits 0 (PoC blocked)
2. `verify-service.ps1` on the DC or CA exits 0 (affected service healthy)

Same dual-gate rule as container-mode `meta4/scenario-NNN/`.

## Teardown

```bash
vagrant destroy -f
```

Snapshots and linked clones are removed; pull the community box again with
`vagrant up` next time. `vagrant box remove jborean93/WindowsServer2019`
frees ~12 GB if you're done for a while.

## Contract for scorer integration

See [`lib/harness-schema.md`](lib/harness-schema.md). Every scenario ships
a `harness.json` declaring `"mode": "vm-ad"` and identifying which VM runs
which script. Scorers MUST dispatch through `./run-scenario.sh NN` rather
than attempting to build a container.
