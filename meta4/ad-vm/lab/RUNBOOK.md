# Hyper-V lab runbook

Every step below needs an **elevated** PowerShell prompt. Steps marked
**[done]** have already been completed and verified; the rest need the
hardware.

Run from `meta4/ad-vm/`.

---

## 0. Host prerequisites

```powershell
# Hyper-V (reboots)
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All

# Pester 5+  [done — 6.0.1 installed]
Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force -SkipPublisherCheck

# AutomatedLab — pin the version and record it in IMAGES.md
Install-Module AutomatedLab -Scope CurrentUser -Force
(Get-Module AutomatedLab -ListAvailable | Select-Object -First 1).Version

# Windows ADK Deployment Tools, for oscdimg (cloud-init seed ISO)
#   https://learn.microsoft.com/windows-hardware/get-started/adk-install
Get-Command oscdimg.exe
```

Also required: the Windows Server 2019 and Ubuntu Server 24.04 ISOs, with
their SHA256 hashes recorded in `IMAGES.md`.

---

## 1. Images  **[partly done]**

**[done]** The attacker tooling image builds and passes its gate:

```powershell
docker build -t srb-attacker:1 .\lab\attacker
# -> tool gate: all 16 scenario dependencies resolve AND execute
```

Still needed — record the ISO hashes, then verify:

```powershell
Get-FileHash -Algorithm SHA256 'C:\LabSources\ISOs\<ws2019>.iso'
# edit lab\IMAGES.md with the real values, then:
. .\lab\Test-ImageChecksums.ps1
Test-ImageChecksums -ManifestPath .\lab\IMAGES.md -ImageDir 'C:\LabSources\ISOs'
```

---

## 2. Switches

`-ExternalAdapterName` is mandatory: on a laptop the only physical adapter is
often Wi-Fi, and an External switch over a wireless NIC works only via
ARP-proxy bridging.

```powershell
Get-NetAdapter -Physical | Select-Object Name, Status, LinkSpeed

. .\lab\New-LabSwitches.ps1
New-LabSwitches -ExternalAdapterName '<your adapter>'
Get-LabSwitchHealth | Format-Table
Test-NoLabNatCollision

# Confirm WSL2 still has its NAT prefix
wsl -e curl -s -o /dev/null -w '%{http_code}' https://example.com   # expect 200
```

---

## 3. Windows lab

```powershell
powershell -ExecutionPolicy Bypass -File .\lab\SysRepairLab.ps1
# 45-90 min. Fails fast with a clear message if LabSources or the ISO is missing.

. .\lab\Protect-ParentDisk.ps1
Set-LabVMHardening -VMName corp-dc01,corp-ca01,corp-ws01
Protect-ParentDisk -ParentVhdxPath (Get-LabParentDiskPath -VMName corp-dc01)
```

Hardening must run **before** any baseline is captured — it removes automatic
checkpoints taken during `Install-Lab` and switches checkpoint type to
Standard.

---

## 4. Attacker VM

```powershell
. .\lab\New-AttackerVM.ps1

New-AttackerSshKey
New-CloudInitSeedIso -CloudInitDir .\lab\attacker\cloud-init -OutputIsoPath C:\srb\seed.iso
New-AttackerVM -UbuntuIsoPath C:\srb\ubuntu-24.04.iso `
               -VhdxPath      C:\srb\attacker01.vhdx `
               -SeedIsoPath   C:\srb\seed.iso

Start-VM attacker01
# Complete the Ubuntu install. The VM is on SRB-Build (internet) on purpose --
# cloud-init installs docker.io. Note the DHCP address from the console.

Install-AttackerTooling -BuildHost <dhcp-address>
Move-AttackerToLabNetwork
Start-VM attacker01
```

---

## 5. Provisioning

```powershell
$cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator',
    (ConvertTo-SecureString 'Password1!' -AsPlainText -Force))

Invoke-Command -VMName corp-dc01 -Credential $cred -FilePath .\provision\seed-directory.ps1
Invoke-Command -VMName corp-ca01 -Credential $cred -FilePath .\provision\ca-postinstall.ps1
```

---

## 6. Readiness and baseline

```powershell
Import-Module .\lab\LabReadiness.psm1 -Force
. .\lab\Start-LabOrdered.ps1
. .\lab\Save-LabBaseline.ps1
. .\lab\Restore-LabBaseline.ps1
. .\lab\Test-LabEgress.ps1

Start-LabOrdered          # ordered boot, clocks verified
Test-LabEgress            # must confirm NO internet from attacker01
Save-LabBaseline          # atomic, cross-machine

Measure-Command { Restore-LabBaseline }   # record this in IMAGES.md
```

---

## 7. Integration tests

The unit tests pass already **[done — 10/10]**. The integration tests need the
running lab:

```powershell
Invoke-Pester .\tests -Output Detailed
```

---

## What is NOT done

Phase 4a — the per-scenario port — is a separate piece of work. Before it,
`run-scenario.sh` still refers to the retired Vagrant path, and the audit found
16 of 20 scenarios invalid independently of the hypervisor. Six have been
repaired so far (04, 07, 08, 10, 12, 19); 03, 05, 09 still carry fail-open
branches, and 01, 05, 11, 16 need redesign rather than repair.

**No score from this suite is publishable until each scenario has passed a
negative control** — failing against a vulnerable box and passing against a
reference fix.
