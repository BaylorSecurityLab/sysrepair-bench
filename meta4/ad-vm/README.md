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

The lab runs on **Hyper-V via AutomatedLab**. The Vagrant/VirtualBox
implementation has been retired — see [Migration status](#migration-status).

- Windows 11 Pro with Hyper-V enabled
- AutomatedLab (pin the version; record it in [`lab/IMAGES.md`](lab/IMAGES.md))
- Pester ≥ 5.0
- Windows ADK Deployment Tools, for `oscdimg` (builds the cloud-init seed ISO)
- Docker, to build the attacker tooling image
- Windows Server 2019 evaluation ISO and Ubuntu Server 24.04 ISO, with SHA256
  hashes recorded in `lab/IMAGES.md`
- ~10 GB free RAM, ~60 GB free disk for four VMs

Full step-by-step setup is in [`lab/RUNBOOK.md`](lab/RUNBOOK.md).

## Quick start

```powershell
# One-time (elevated). Full detail in lab/RUNBOOK.md.
. .\lab\New-LabSwitches.ps1;     New-LabSwitches -ExternalAdapterName '<adapter>'
powershell -ExecutionPolicy Bypass -File .\lab\SysRepairLab.ps1
. .\lab\Protect-ParentDisk.ps1;  Set-LabVMHardening
. .\lab\New-AttackerVM.ps1;      New-AttackerSshKey; New-AttackerVM ...
. .\lab\Save-LabBaseline.ps1;    Save-LabBaseline

# Per scenario
./run-scenario.sh 13                    # restore -> inject -> handoff
./run-scenario.sh 13 --verify-only      # grade; exits 0 iff both gates pass
```

**There is no manual wait step.** The previous implementation needed one
because Vagrant could not survive `Install-ADDSForest` destroying the local
SAM mid-session, which invalidated the WinRM session it was holding.
AutomatedLab's `RootDC` role promotes the DC out of band, so the entire
self-driving bootstrap chain — the scheduled task, the reboot dance, the
30-minute marker poll — is gone.

<details>
<summary>Retired Vagrant bringup (kept for reference)</summary>

Fresh-clone DC bringup used to require a two-step dance: `vagrant up dc`
would time out mid-DCPROMO with a WinRM auth error, but the bootstrap chain
kept running in the background on the VM. You waited for it to finish, then
brought up the other two VMs.

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

</details>

## VMs

| Role | VM name | IP | Notes |
|---|---|---|---|
| DC / forest root | `corp-dc01` | `10.20.30.5` | `corp.local` / `CORP` NetBIOS. Fixed 3 GB — AD's ESE cache sizes at boot, so this must not balloon. |
| Enterprise CA | `corp-ca01` | `10.20.30.6` | Member server, ADCS EnterpriseRootCA, CN pinned to `corp-ca01-CA` |
| Member workstation | `corp-ws01` | `10.20.30.20` | Domain member. Enables the behavioural PoCs for S13, S15, S17 and S19. |
| Attacker | `attacker01` | `10.20.30.10` | Ubuntu Server running the pinned `srb-attacker` Kali tooling container. `corp\alice:Password1!` in `~/creds.txt`. |

All four sit on the `SRB-Lab` Internal switch, which has no route to the
internet — verified from inside the guest by `Test-LabEgress`, not merely
asserted from the switch type.

## Scenario matrix

All 20 scenarios are present and all 20 now dispatch. **They are not all
valid, and none is publishable yet** — see [Migration status](#migration-status).

An earlier version of this section claimed "behavioral PoC + service probes —
no config-only checks". That claim did not hold: at least S11, S13 and S18 read
configuration rather than performing the attack, and the toolchain the PoCs
depend on was never installed. It is corrected here rather than quietly
dropped.

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
2. `verify-service.ps1` on its target machine exits 0 (affected service healthy)

Same dual-gate rule as container-mode `meta4/scenario-NNN/`.

`verify-poc.sh` exit codes are three-valued, and the distinction matters:

| Exit | Meaning |
|---|---|
| 0 | PoC blocked — the host is remediated |
| 1 | PoC succeeded, or the result was inconclusive |
| **2** | **Harness error** — a grader tool is missing or broken |

**Exit 2 is never evidence of anything.** It exists because the original suite
graded missing tools as "attack blocked": `/usr/bin/certipy-ad` did not exist,
the PoC's `|| true` swallowed the error, and a fail-open branch reported PASS
on an untouched vulnerable box. A scenario returning 2 is a broken harness, not
a remediated host.

## Validating a scenario — the four proof gates

A green dual gate proves nothing on its own; the broken checks were green too.
`lab/Test-ScenarioGates.ps1` runs each scenario through the four gates from the
project's verify-check hardening methodology:

| Gate | What it runs | Required result |
|---|---|---|
| 1 — baseline fails for the right reason | restore → inject | PoC exits **1** (attack works), and **not 2**; service healthy |
| 2 — still solvable | apply `reference-fix.ps1` | both gates pass |
| 3 — sabotage | re-apply `inject.ps1` | PoC fails again |
| 4 — not-restarted | apply `reference-fix-norestart.ps1` | PoC **still fails** |

Gate 4 is the one that catches config-only checks: it applies the correct
configuration without restarting the affected service, so a check that greps a
file rather than exercising the running service will wrongly pass. It only
applies where the remediation involves a service — scenarios whose fix is a
pure directory change record it as not-applicable rather than passing silently.

```powershell
. .\lab\Test-ScenarioGates.ps1
Test-ScenarioGates -ScenarioId 06        # one scenario
Get-ScenarioFixtureCoverage              # which fixtures exist

. .\lab\Invoke-FullGateRun.ps1
Invoke-FullGateRun                       # all 20; ~90 min; writes gate-results.json
```

### Fixtures

Each scenario ships `reference-fix.ps1` — the reference remediation, used only
by the gates and never shown to an agent. Scenarios whose fix needs a service
restart also ship `reference-fix-norestart.ps1` for gate 4.

Fixtures are deliberately **narrow**: the exact inverse of the inject, not a
wholesale reset. A blunt reset would mask the vulnerability while changing far
more than the scenario is about, and would make gate 3 meaningless. Each one
verifies its own effect rather than trusting the write.

## Teardown

```powershell
Remove-Lab -Name SysRepairBench          # the three Windows machines
Remove-VM -Name attacker01 -Force        # built outside AutomatedLab
```

Remove the `SRB-Lab`, `SRB-Build` and `SRB-Kernel` switches with
`Remove-VMSwitch` if you are done entirely.

## Migration status

The lab was ported from Vagrant + VirtualBox to Hyper-V + AutomatedLab. What
that fixed, and what it did not:

**Done.** VM creation, DC promotion, CA install, ordered boot with
service-level readiness gating, clock verification, atomic cross-machine
baseline capture, and scenario dispatch with post-handoff grader staging. The
attacker tooling image builds with every tool the scenarios invoke resolving
*and executing*.

**Retired but still on disk.** `Vagrantfile`, `reset.sh`,
`capture-baselines.sh`, `provision/dc-baseline.ps1`, `provision/ca-baseline.ps1`
and `provision/attacker-baseline.sh` are superseded and no longer referenced by
`run-scenario.sh`. They are kept until the Hyper-V path has completed one
successful run on real hardware, then deleted.

**Not done — and this gates publication.** An audit of all 20 scenarios found
the graders themselves broken, independently of the hypervisor. The root cause
was a provisioning bug: tools were installed under names and paths the
scenarios never call, every symlink was silently skipped, and fail-open
branches then graded "PoC BLOCKED" — a PASS on an unmodified vulnerable box.

Repaired so far: **03, 04, 07, 08, 09, 10, 12, 14, 19**.

Still outstanding:

| Scenario | Problem |
|---|---|
| S01 Zerologon | `zerologon_tester` is not an impacket tool; the image now supplies it from upstream, but the scenario needs revalidation |
| S05 Unconstrained delegation | `getST -impersonate` as a plain user is S4U2self, which requires the *requesting* account to hold delegation rights — the probe can never observe what it grades |
| S11 ESC8 | The documented EPA remediation still returns HTTP 200 and the banner, so a correct fix is penalised |
| S16 PrintNightmare | Grades the wrong vulnerability: `spoolsample` is MS-RPRN coercion (PrinterBug), while `threat.md` describes `RpcAddPrinterDriverEx` |

**No score from this suite is publishable until each scenario has passed a
negative control** — failing against an unmodified vulnerable box and passing
against a reference fix. That fixture does not exist yet.

## Contract for scorer integration

See [`lib/harness-schema.md`](lib/harness-schema.md). Every scenario ships
a `harness.json` declaring `"mode": "vm-ad"` and identifying which VM runs
which script. Scorers MUST dispatch through `./run-scenario.sh NN` rather
than attempting to build a container.
