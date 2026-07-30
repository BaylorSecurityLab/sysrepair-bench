# meta3/windows-vm — deploy + validate RUNBOOK

Precise steps for LATER (when host RAM frees and Hyper-V is available). Nothing
here should be run on a RAM-constrained host or while another session owns
Hyper-V. This suite is **authored only** right now.

## Prerequisites

- Windows 11 host with **Hyper-V** enabled and an **elevated** PowerShell.
- **AutomatedLab** installed (`Install-Module AutomatedLab -Scope AllUsers`).
- **~10 GB free RAM** for the single Server 2019 VM (3 GB assigned + overhead)
  and ~40 GB free disk.
- **Windows Server 2019 Evaluation ISO** at `C:\LabSources\ISOs\WindowsServer2019Eval.iso`
  (same `LabSources\ISOs` convention meta4/ad-vm uses).
- `jq` on the host (only if you dispatch via a jq-parsing scorer; `run-scenario.sh`
  here resolves the scenario dir by glob and does not require jq).

## Shared infra reuse (from meta4/ad-vm)

- Same Hyper-V + AutomatedLab host role and the same `C:\LabSources\ISOs` layout.
- `lab/Repair-LabBaseImage.ps1` is copied verbatim from `meta4/ad-vm/lab` — it
  repairs the empty-EFI-System-partition base image AutomatedLab produces on a
  Win11 host newer than the Server 2019 guest. Run
  `Test-LabBaseImageBootable` after Install-Lab creates the base image; if a
  base VHDX shows `Bootable = $false`, run `Repair-LabBaseImage` before the VM
  is expected to boot.

## 1. Build the lab

```powershell
# elevated PowerShell, from meta3/windows-vm
.\lab\SysRepairLab.ps1
# If Install-Lab hangs on a never-booting VM:
. .\lab\Repair-LabBaseImage.ps1 ; Test-LabBaseImageBootable ; Repair-LabBaseImage -Verbose
```

`SysRepairLab.ps1` builds `META3WIN`, then copies and runs
`provision/baseline.ps1` inside it. Supply the eval bridge public key first so
the scorer's SSH bridge works:

```powershell
# generate the bridge keypair the eval host will use, drop the pubkey where
# SysRepairLab.ps1 reads it (build/bridge_key.pub)
mkdir ..\build -Force
ssh-keygen -t ed25519 -N '""' -f ..\build\bridge_key -C sysrepair-bridge
# (SysRepairLab.ps1 reads build\bridge_key.pub automatically)
```

## 2. Snapshot the hardened baseline

```powershell
.\lab\Save-LabBaseline.ps1
```

Verify the hardened baseline is correct (all three should report the *secure*
state) BEFORE injecting anything:

```powershell
Import-Lab SysRepairMeta3 -NoValidation
Invoke-LabCommand META3WIN -ScriptBlock {
    (Get-SmbServerConfiguration | Select EnableSMB1Protocol, RequireSecuritySignature)
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication, SecurityLayer
    Get-NetTCPConnection -LocalPort 445,3389 -State Listen | Select LocalPort
}
# Expect: EnableSMB1Protocol=False, RequireSecuritySignature=True,
#         UserAuthentication=1, SecurityLayer=2, 445 + 3389 listening.
```

## 3. Per-scenario baseline-vulnerable -> solved (validation)

For each scenario NN in 10, 11, 12:

```bash
# git-bash on the host (or call the .ps1 helpers directly from PowerShell)
./run-scenario.sh NN                 # restore baseline -> stage -> inject vuln

# (a) prove BASELINE-VULNERABLE: verify must FAIL right after inject
./run-scenario.sh NN --verify-only ; echo "exit=$?"   # expect exit=1 (poc fails)

# (b) apply the reference solution INSIDE the VM
```
```powershell
Import-Lab SysRepairMeta3 -NoValidation
$dir = (Get-ChildItem ..\ -Directory -Filter "scenario-NN-*").Name
Invoke-LabCommand META3WIN -ScriptBlock { & "C:\sysrepair\$using:dir\solution.ps1" }
```
```bash
# (c) prove SOLVED: verify must now PASS
./run-scenario.sh NN --verify-only ; echo "exit=$?"   # expect exit=0 (both gates pass)
```

Expected per scenario:

| NN | inject makes live probe say | solution.ps1 does | post-fix probe says |
|----|-----------------------------|-------------------|---------------------|
| 10 | SMB1 accepted (445) | `Set-SmbServerConfiguration -EnableSMB1Protocol $false` + restart | SMB1 rejected -> SMB2 |
| 11 | signing optional (445) | `Set-SmbServerConfiguration -RequireSecuritySignature $true` + restart | signing required |
| 12 | plain RDP accepted (3389) | `UserAuthentication=1; SecurityLayer=2` + restart TermService | plain RDP rejected/upgraded |

A scenario is validated when (a) fails and (c) passes, and `verify-service.ps1`
passes throughout (service Running, port listening) — proving the fix did not
"cheat" by stopping the service.

## 4. Scorer integration (SSH bridge)

The eval scorer (`inspect_eval/sysrepair_bench/scorer.py`) reaches a Windows VM
over SSH when `os == "windows"` and `bridge_target_host` is in the sample
metadata (SCPs `verify.ps1` + `roles.json` to `C:\ProgramData\sysrepair\` and
runs it there). The OpenSSH bridge that `provision/baseline.ps1` installs
(port 22, key = `build/bridge_key`) makes that path usable. See "Open questions"
in the authoring notes: `task.py` currently populates that metadata only for
Vagrant VMs (`_prepare_vagrant_bridge`), so an AutomatedLab equivalent (or a
thin `_prepare_automatedlab_bridge`) is still needed to wire this suite into the
scorer. Until then, use `run-scenario.sh NN --verify-only` for local scoring.

## Teardown

```powershell
Import-Lab SysRepairMeta3 -NoValidation ; Remove-Lab -Name SysRepairMeta3 -Confirm:$false
```
