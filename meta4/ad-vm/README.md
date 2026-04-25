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

## Quick start (manual route)

Fresh-clone DC bringup currently requires a two-step dance: `vagrant up dc`
will time out mid-DCPROMO with a WinRM auth error, but the bootstrap chain
keeps running in the background on the VM. You wait for it to finish, then
bring up the other two VMs.

```bash
cd meta4/ad-vm

vagrant plugin install vagrant-reload   # first time only

# --- step 1: DC (expect a WinRM timeout; that's fine) ---
vagrant up dc
#   ==> dc: [dc-baseline] pass 1 complete; awaiting reload + bootstrap.ps1 chain
#   ==> dc: Running provisioner: reload...
#   ==> dc: [dc-baseline] AD DS role installed; waiting for Meta4-Bootstrap chain to finish
#   WinRM::WinRMAuthorizationError                              <-- expected on fresh clone

# --- step 2: wait ~10-15 min, then poll until the DC reports ready ---
while [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:55985/wsman)" != "405" ]; do
    echo "waiting for DC WinRM to come back up..."; sleep 30
done

vagrant winrm dc -s powershell -c "(Get-ADDomain).DNSRoot; Test-Path C:\meta4-setup\BOOTSTRAP_COMPLETE"
#   corp.local
#   True                                                        <-- DC is fully baked

# --- step 3: CA + attacker (these run cleanly, no manual wait) ---
vagrant up ca
vagrant up attacker

# --- step 4: baseline snapshot + smoke test ---
./capture-baselines.sh                  # one-time snapshot capture

./run-scenario.sh 13                    # restore + inject S13
ssh vagrant@10.20.30.10                 # (password: vagrant)
#   ~/threat.md  ~/creds.txt  ~/tools/ → /opt/ad-tools/bin

# When the agent signals done:
./run-scenario.sh 13 --verify-only      # exits 0 iff both checks pass
```

### Why the DC bringup times out

`Install-ADDSForest` strips the local SAM the moment it runs, which
invalidates the WinRM session vagrant is holding during pass-2's
"wait for bootstrap" loop. The bootstrap chain (DCPROMO + directory
seeding + Meta4-Bootstrap Phase B) runs to completion on the VM regardless,
writing `C:\meta4-setup\BOOTSTRAP_COMPLETE` when done. The manual wait
above just holds off on the next step until that marker exists.

If `curl` shows `winrm=000` for more than 25 min after the timeout,
something broke — open the VirtualBox GUI (`VBoxManage startvm meta4-ad-dc
--type separate`) or RDP to `127.0.0.1:3389` as `Administrator` /
`Vagrant1DSRM!` and check `C:\meta4-setup\bootstrap.log`.

## VMs

| Role | VM name | IP | Notes |
|---|---|---|---|
| DC / forest root | `corp-dc01` | `10.20.30.5` | `corp.local` / `CORP` NetBIOS |
| Enterprise CA | `corp-ca01` | `10.20.30.6` | Member of corp.local, ADCS EnterpriseRootCA |
| Kali attacker | `kali-attacker` | `10.20.30.10` | `corp\alice:Password1!` seeded in `~/creds.txt` |

## Scenario matrix

All 20 scenarios shipped (Phase 0–4 complete; final Phase 4 batch landed
2026-04-24). Each ships behavioral PoC + service probes — no config-only
checks. User-side smoke validation pending.

| # | Title | Category | Severity | CVE | Comp-ctrl | Shipped |
|---|---|---|---|---|---|---|
| 01 | Zerologon | Access Control | Critical | CVE-2020-1472 | No | ✓ |
| 02 | MachineAccountQuota foothold (NoPac chain) | Access Control | Critical | CVE-2021-42278 / 42287 | No | ✓ |
| 03 | Kerberoasting | Compensating Controls | High | n/a | Yes | ✓ |
| 04 | AS-REP roasting | Compensating Controls | High | n/a | Yes | ✓ |
| 05 | Unconstrained delegation | Compensating Controls | High | n/a | Yes | ✓ |
| 06 | DCSync rights to non-admin | Access Control | Critical | n/a | No | ✓ |
| 07 | ADCS ESC1 | Configuration Hardening | Critical | n/a | Yes | ✓ |
| 08 | ADCS ESC2 | Configuration Hardening | Critical | n/a | Yes | ✓ |
| 09 | ADCS ESC3 | Configuration Hardening | High | n/a | Yes | ✓ |
| 10 | ADCS ESC6 | Configuration Hardening | Critical | n/a | Yes | ✓ |
| 11 | ADCS ESC8 (Web Enrollment relay surface) | Configuration Hardening | Critical | n/a | Yes | ✓ |
| 12 | LDAP signing not required | Compensating Controls | High | n/a | Yes | ✓ |
| **13** | **SMB signing disabled (smoke test)** | **Compensating Controls** | **High** | **n/a** | **Yes** | **✓** |
| 14 | NTLMv1 allowed | Compensating Controls | High | n/a | Yes | ✓ |
| 15 | LLMNR / NBT-NS responder | Network Security | Medium | n/a | Yes | ✓ |
| 16 | PrintNightmare (CVE-2021-34527) | Dependency Management | Critical | CVE-2021-34527 | Yes | ✓ |
| 17 | PetitPotam / EFSRPC coercion | Configuration Hardening | High | CVE-2021-36942 | Yes | ✓ |
| 18 | GPP cpassword in SYSVOL | Access Control | High | n/a | No | ✓ |
| 19 | LAPS not enforced | Access Control | Medium | n/a | Yes | ✓ |
| 20 | AdminSDHolder backdoor ACL | Access Control | Critical | n/a | No | ✓ |

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
