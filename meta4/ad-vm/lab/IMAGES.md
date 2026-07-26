# Image provenance

Every artifact this lab is built from, with the checksum it was built against.

Verify before building:

```powershell
. .\Test-ImageChecksums.ps1
Test-ImageChecksums -ManifestPath .\IMAGES.md -ImageDir 'C:\LabSources\ISOs'
```

## ISOs — download these yourself

| File | Alg | Hash |
|---|---|---|
| 17763.3650.221105-1748.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso | SHA256 | 6DAE072E7F78F4CCAB74A45341DE0D6E2D45C39BE25F1F5920A2AB4F51D7BCBB |
| ubuntu-24.04.2-live-server-amd64.iso | SHA256 | D6DAB0C3A657988501B4BD76F1297C053DF710E06E0C3AECE60DEAD24F270B4D |

Windows Server 2019 build 17763.3650 (rs5_release_svc_refresh, 2022-11-05),
Ubuntu Server 24.04.2 LTS. Regenerate with:

```powershell
Get-ChildItem C:\LabSources\ISOs\*.iso | Get-FileHash -Algorithm SHA256
```

**Edition string.** `Install-Lab` exact-matches `-OperatingSystem` against
`Get-LabAvailableOperatingSystem`. The evaluation media reports
`Windows Server 2019 Datacenter Evaluation (Desktop Experience)` — note
"Evaluation", which the retail spelling omits. A different ISO may report a
different string; the preflight in `SysRepairLab.ps1` prints the available
list when it does not match.

Windows Server 2019 is a 180-day evaluation image from the Microsoft Evaluation
Center. **The evaluation licence gives this artifact a hard expiry.** Reviewers
reproducing after that window must obtain a current evaluation ISO and re-run
the phase 1 bake; the recorded hash will differ, and that is expected rather
than a reproducibility failure.

## Container images

| Image | Digest |
|---|---|
| kalilinux/kali-rolling | `sha256:dea2bdf0e8c0ca1deb51b7a6253f481acae3ca9c2f1e2371077e6af55e5b2721` |

## Upstream research tools, pinned by commit

Three tools the scenarios invoke exist in no distribution package at any
version. They are cloned at fixed commits during the image build.

| Repo | Commit | Used by |
|---|---|---|
| `SecuraBV/CVE-2020-1472` | `93b7e276c2fea9a4149a631c0d359f9b45dc45a9` | S01 (`impacket-zerologon_tester`) |
| `topotam/PetitPotam` | `c5d5221dc5e6aac3bc7de97a34fa8d89c2f1900b` | S17 (`impacket-PetitPotam`) |
| `dirkjanm/krbrelayx` | `10b45a33bc4361ec4a5546eea62db2e4244d3255` | S16 (`impacket-spoolsample` → `printerbug.py`) |

## Toolchain

Everything else comes from Kali's own packages. Nothing is pip-installed:
apt supplies correct binary names for every tool the scenarios call —
including `certipy-ad` at `/usr/bin/certipy-ad` — and avoids a venv whose
Python version can break a package's imports.

| Component | Source | Notes |
|---|---|---|
| `impacket-scripts` | Kali apt | Provides the `/usr/bin/impacket-*` names. `python3-impacket` alone ships only five of them. |
| `certipy-ad` | Kali apt | v5.1.0. Provides `/usr/bin/certipy-ad` directly — the exact path S07–S10 call. |
| `responder` | Kali apt | Installs to `/usr/sbin/responder`; the image symlinks it to `/usr/bin/responder`, which is what `scenario-14` calls. |
| `freerdp3-x11` | Kali apt | Provides both `xfreerdp` and `xfreerdp3`. |
| `hashcat`, `netexec`, `bloodhound.py` | Kali apt | |
| AutomatedLab | PowerShell Gallery | **Pin with `-RequiredVersion`.** Record the version used here: RECORD-ON-INSTALL |
| Pester | PowerShell Gallery | 5.0.0 or later |

## Reproducibility claim

This records a **documented build procedure plus verified input checksums**.
It does not claim bit-identical output images: sysprep is nondeterministic, so
two runs of the bake produce different VHDX hashes. The reproducible artifacts
are the inputs and the procedure.
