# SysRepair-Bench: Metasploitable 3 Extension

Two OS-specific sub-suites of the SysRepair-Bench scenario format (see the [root README](../README.md) for benchmark overview, scenario layout, host requirements, and harness usage):

- [`ubuntu/`](ubuntu/README.md) — Linux targets from **Metasploitable 3 (Ubuntu 14.04)**. Scoped by [`../openvas-scan-reports/metasploitable-3.0-ubu-openvas.pdf`](../openvas-scan-reports/metasploitable-3.0-ubu-openvas.pdf) plus the Meta3-Ubuntu design surface (Drupal, ProFTPD, payroll app, credential reuse).
- [`windows/`](windows/README.md) — Windows targets from **Metasploitable 3 (Windows Server 2008 R2)**. Scope ported from the [Rapid7 metasploitable3 Packer/Vagrant build scripts](https://github.com/rapid7/metasploitable3) and cross-checked against [`../openvas-scan-reports/metasploitable-3.0-win-openvas.pdf`](../openvas-scan-reports/metasploitable-3.0-win-openvas.pdf).

The two sub-suites live side by side because Meta3 ships two distinct target images (Ubuntu 14.04 and Windows Server 2008 R2) with non-overlapping vulnerability surfaces and toolchains — keeping them in sibling folders lets the harness pick per-OS targets without skipping half the suite.

## Status

| Sub-suite | Scan source | Scenario count | State |
|---|---|---|---|
| [`ubuntu/`](ubuntu/README.md) | OpenVAS scan (Apr 2026) committed | 19 live (S01–S19) | Dockerfiles, threat.md, verify.sh, Chef run-lists all stamped; vendored Rapid7 cookbook under [`ubuntu/shared/`](ubuntu/shared/README.md) |
| [`windows/`](windows/README.md) | OpenVAS scan committed ([PDF](../openvas-scan-reports/metasploitable-3.0-win-openvas.pdf)) | 21 live (S01–S21) | Dockerfiles / Packer / Hyper-V providers, threat.md, behavioral verify probes, sequential harness in [`windows/run-sequential.ps1`](windows/run-sequential.ps1) |

See each sub-suite's README for the full scenario index and any suite-specific build notes.
