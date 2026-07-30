# meta3/windows-vm — standalone Windows Server SMB/RDP VM harness

AutomatedLab-provisioned Windows Server 2019 **standalone** member (workgroup,
no domain controller) hosting three SysRepair-Bench scenarios whose grading
requires a **live** protocol negotiation that a Windows container cannot host:

| # | Scenario | Live probe | Why not a container |
|---|---|---|---|
| 10 | SMBv1 enabled (EternalBlue precondition) | raw SMB1 NEGOTIATE vs 445 | `srvnet.sys` won't load in a container; 445 never listens |
| 11 | SMB signing not required (NTLM relay) | raw SMB2 NEGOTIATE + SecurityMode vs 445 | same — no live SMB server |
| 12 | RDP NLA disabled (pre-auth surface) | raw TPKT/X.224 RDP negotiation vs 3389 | `TermService` won't start in a container; 3389 never listens |

These port the check logic and the `*_probe.ps1` scripts from the interim
container versions in [`../windows/scenario-{10-smbv1,11-smb-signing,12-rdp-nla}`](../windows).
On a real VM the SMB/RDP services actually run, so the probes reach a live
listener instead of asserting persisted registry state.

## Model (mirrors meta4/ad-vm)

One lab, per-scenario inject on a restored baseline:

1. `lab/SysRepairLab.ps1` builds a single hardened Server 2019 VM (`META3WIN`).
2. `provision/baseline.ps1` leaves it HARDENED: SMB1 off, SMB signing required,
   RDP NLA on, OpenSSH bridge up, a weak local admin created.
3. `lab/Save-LabBaseline.ps1` snapshots that hardened state.
4. Per scenario: `run-scenario.sh NN` restores baseline, stages `scenario-NN/`,
   runs `inject.ps1` (introduces exactly one live vuln + restarts the service).
5. `run-scenario.sh NN --verify-only` runs the two gates and passes iff both:
   * `verify-poc.ps1` — the LIVE probe (PoC blocked => remediated), and
   * `verify-service.ps1` — service Running AND port genuinely listening.

## Per-scenario contract

Each `scenario-NN-*/` ships: `harness.json`, `inject.ps1`, `threat.md`,
`verify-poc.ps1`, `verify-service.ps1`, the `*_probe.ps1` live probe, and
`solution.ps1` (reference remediation used by deploy+validate to prove
solvability). `harness.json` declares `"mode": "vm-standalone"` with all targets
pointing at the single `member` VM.

## Status

**Authored, not yet deployed.** VMs are built + validated LATER when host RAM
frees. The interim container rows (`meta3-windows/scenario-10..12`) stay in
`scenarios.jsonl` until these VMs are validated. See [`lab/RUNBOOK.md`](lab/RUNBOOK.md)
for the exact deploy+validate sequence.
