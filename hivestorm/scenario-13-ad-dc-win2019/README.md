# scenario-13-ad-dc-win2019 — divergent invocation

Unlike the Docker-native scenarios, this one is a **Vagrant VM**: Active
Directory Domain Services cannot be hosted inside a Windows Server-Core
container (no `ADDSDeployment` module support, no reboot semantics). It
follows the same VM pattern as `meta3/windows/`.

## Prereqs

- Vagrant ≥ 2.3
- VirtualBox ≥ 6.1 (or Hyper-V; `Vagrantfile` uses the VirtualBox provider
  by default, edit to switch)
- The `gusztavvargadr/windows-server-2019-standard` box (Vagrant Cloud)

## Build flow

```bash
# 1. Generate roles.json + render task.md (same as Docker scenarios)
hivestorm/prepare.sh 13

# 2. Bring up the VM — provisioner promotes to DC, reboots, then runs seed.ps1
cd hivestorm/scenario-13-ad-dc-win2019
vagrant up
```

First boot takes ~15 minutes (ADDS promotion + reboot + seed). Subsequent
`vagrant up` of a previously provisioned VM skips the provisioner.

## Running the verifier

The Inspect-AI harness invokes `verify.ps1` over WinRM. For manual runs:

```bash
vagrant winrm -s powershell -c 'C:\ProgramData\sysrepair\verify.ps1'
```

JSONL output is captured and scored by `hivestorm_weighted_scorer`.

## Scope caveats

- **Single-DC / single-domain only.** Cross-forest trusts, child domains,
  and RODCs are out of scope for sysrepair-bench and deferred to a future
  `hivestorm-ad/` suite.
- **Krbtgt dual rotation** is documented in the scoring rubric but only a
  single rotation is checked — full dual-rotation testing requires replay
  of Kerberos tickets, which the harness does not orchestrate.
- **LAPS** is represented as "not deployed" rather than "deployed but
  misconfigured" — the agent is credited for either installing LAPS or
  documenting via a decoy registry marker that a manual workflow exists.
