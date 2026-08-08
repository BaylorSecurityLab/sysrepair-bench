# meta3/windows-vm — deploy + validate RUNBOOK

Precise steps for LATER (when host RAM frees and Hyper-V is available). Nothing
here should be run on a RAM-constrained host or while another session owns
Hyper-V. This suite is **authored only** right now.

## Prerequisites

- Windows 11 host with **Hyper-V** enabled and an **elevated** PowerShell.
- **AutomatedLab** installed (`Install-Module AutomatedLab -Scope AllUsers`).
- **~10 GB free RAM** for the single Server 2019 VM (3 GB assigned + overhead)
  and ~40 GB free disk.
- **Windows Server 2019 Evaluation ISO** anywhere under `C:\LabSources\ISOs`
  (same convention meta4/ad-vm uses). The filename is **not** hardcoded —
  `SysRepairLab.ps1` discovers it, and resolves the edition from the media too,
  so eval-vs-retail edition naming does not have to be guessed.
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

---

## RESOLVED (2026-08-08): poisoned `LocalIsoImages` registry cache

The blocker recorded below was a **stale AutomatedLab ISO cache**, not anything
in this repo's lab definition. Root cause and the A/B that proves it:

`AutomatedLabCore.psm1:14403` tests `$lab.Sources.AvailableOperatingSystems`.
That property has **no backing field** — decompiling its getter out of
`AutomatedLab.dll` gives

    isos.Cast<IsoImage>().SelectMany(i => i.OperatingSystems).ToList()

so it is 0 whenever every ISO in the lab carries an **empty** `OperatingSystems`
list. That is why `.ISOs` looked healthy (2 correct paths) while the check still
threw, and why every experiment in the table below moved nothing.

`HKCU:\Software\AutomatedLab\Cache\LocalIsoImages` held, verbatim:

    <IsoImage><Name>Server2019</Name>
      <Path>C:\LabSources\ISOs\17763.3650...SERVER_EVAL_x64FRE_en-us.iso</Path>
      <Size>5652088832</Size><OperatingSystems /></IsoImage>

`<Name>Server2019</Name>` is the tell: `New-LabDefinition`'s auto-add names ISOs
`[guid]::NewGuid()` (`AutomatedLabDefinition.psm1:501`), so that entry was
written by a **manual** `Add-LabIsoImageDefinition -Name Server2019` from an
earlier revision of `SysRepairLab.ps1`.

**Why a manual call poisons the cache.** `Add-LabIsoImageDefinition` guards its
"mount the ISO and read its editions" block with
(`AutomatedLabDefinition.psm1:525`)

    if (-not $script:lab.DefaultVirtualizationEngine -eq 'Azure')

which PowerShell parses as `((-not $engine) -eq 'Azure')`. New-LabDefinition's
own auto-add runs at `:3020`, **before** `DefaultVirtualizationEngine` is
assigned at `:3026` — so `-not ''` → `$true -eq 'Azure'` → `$true`, the block
runs, editions are read. A manual call *after* `New-LabDefinition` sees
`'HyperV'` — `-not 'HyperV'` → `$false -eq 'Azure'` → `$false` — the block is
skipped, `$isOperatingSystem` stays `$null`, and the ISO is cached with zero
editions (`:554`) and written to the registry (`:578`). From then on every
`New-LabDefinition` matches that entry by Path+Size (`:513`) and **reuses the
empty object instead of re-reading the media**. Deleting the manual call, which
an earlier revision did, therefore does not recover: the poison outlives it.

**A/B on this host**, same probe script, one variable changed:

| | ISOs | AvailableOperatingSystems | Server 2019 ISO entry |
|---|---|---|---|
| before purge | 2 | **0** | name `Server2019`, OSes=0 |
| after purging `LocalIsoImages` | 2 | **4** | GUID name, OSes=4 |

4 matches the already-built `SysRepairBench` lab exactly
(`Import-Lab SysRepairBench -NoValidation; (Get-Lab).Sources`).

`SysRepairLab.ps1` step **0a** now detects and purges this automatically, because
the failure is opaque (AutomatedLab reports a missing ISO when the ISO is present
and readable) and any future `Add-LabIsoImageDefinition` re-poisons it. To fix it
by hand instead:

```powershell
Remove-ItemProperty HKCU:\Software\AutomatedLab\Cache -Name LocalIsoImages
```

Also corrected while here: `lab/Repair-LabBaseImage.ps1` was **not** the verbatim
copy of `meta4/ad-vm/lab` this document claimed — it was missing
`Set-LabBaseImageDriveLetters` and `Clear-LabBaseImageDriveLetters`. It has been
re-synced.

Not a factor, contrary to the guess in "Next steps" below: `TrustedHosts` was
already `*` and `Enable-LabHostRemoting` was never needed.

---

## BLOCKER (2026-08-07), superseded by the section above — kept for the record

Three real script bugs were found by actually running the build and are FIXED
(see git log): `[int] $Memory = 3072MB` overflowing Int32, `-DomainName ''`
failing ValidatePattern on a deliberately workgroup machine, and a hardcoded
ISO filename plus a hardcoded edition string that do not match the evaluation
media. Media and edition now resolve by discovery:

    [lab] Server 2019 media: 17763.3650...SERVER_EVAL_x64FRE_en-us.iso
    [lab] OS edition:        Windows Server 2019 Datacenter Evaluation (Desktop Experience)

The build now reaches `Install-Lab` and dies there:

    - Creating base images
    There isn't a single operating system ISO available in the lab.

### What is actually failing

`AutomatedLabCore.psm1:14405` tests **`$lab.Sources.AvailableOperatingSystems`**
-- NOT `.ISOs`. `.ISOs` is populated (2 entries, correct paths), which is what
makes this misleading.

Measured on this host:

| state | ISOs | AvailableOperatingSystems |
|---|---|---|
| after `New-LabDefinition` | 2 | **0** |
| after `Get-LabAvailableOperatingSystem -Path` | 2 | **0** |
| after the same call with no `-Path` | 2 | **0** |
| after `Add-LabIsoImageDefinition` | 2 | **0** |
| with the OS cache warmed BEFORE `New-LabDefinition` | 2 | **0** |

`Get-LabAvailableOperatingSystem` itself works and returns 6 editions every
time, so the media is readable and the edition string is right.

### Ruled out

- ISO filename / edition string (both now discovered, and printed above).
- Registering the ISO explicitly, omitting it, or doing either before/after
  `New-LabDefinition`.
- Passing the OS as a name vs. as an object.
- Ordering preflight before the lab definition (now matches meta4/ad-vm).
- A cold OS cache: warming it first changes nothing, and the registry cache
  `HKCU:\Software\AutomatedLab\Cache\LocalOperatingSystems` exists.

### Red herring, recorded so nobody re-chases it

`C:\ProgramData\AutomatedLab\Labs\SysRepairMeta3\Lab.xml` is 2726 bytes with
zero `OperatingSystemName` entries and no META3WIN, against 27 KB / 7 entries
for the working `SysRepairBench` lab. That is a STUB written by
`New-LabDefinition`; the real export happens later and never runs because the
throw precedes it. It is a symptom of failing early, not the cause.

### Next steps for whoever picks this up

meta4/ad-vm's `SysRepairBench` lab WAS built successfully on this same host with
the same module version and the same ISO, so this is reproducible-in-principle.
Compare a live `Get-Lab` from that lab against a fresh definition, ideally in an
interactive elevated session where `$lab.Sources` can be inspected directly.
`Enable-LabHostRemoting -Force` (installation.md D6) has not been re-confirmed
in this session and is worth ruling in or out first.
