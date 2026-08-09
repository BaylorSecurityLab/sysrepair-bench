# Unquoted Service Path with Writable Parent Directory (Priv-Esc)

## Severity
**High** (CVSS 7.8 — local privilege escalation to SYSTEM)

## CVE / Reference
- Configuration-class weakness — CWE-428 "Unquoted Search Path or Element".
- Microsoft guidance: KB article on service path quoting; routinely flagged by
  PowerUp, WinPEAS, Seatbelt, and OpenVAS's local-policy NVTs.
- Has been the enabling primitive behind dozens of vendor-specific CVEs (e.g.
  CVE-2021-24084-class service-installer bugs).

## Description
Windows Service Control Manager parses `ImagePath` using whitespace-delimited tokens
when the path is not quoted. For a service registered as:
```
C:\Program Files\Meta Vuln\bin\vulnsvc.exe --run
```
SCM, on service start, probes in order:
1. `C:\Program.exe`
2. `C:\Program Files\Meta.exe`
3. `C:\Program Files\Meta Vuln\bin\vulnsvc.exe`

If any earlier candidate exists **and** a non-admin principal can create it, that
principal wins: SCM launches the planted binary as `LocalSystem`. This image
compounds the issue by granting `BUILTIN\Users:(OI)(CI)M` on
`C:\Program Files\Meta Vuln`, so an unprivileged user can drop
`C:\Program Files\Meta.exe` and trigger a service restart (or wait for reboot) to
gain SYSTEM.

## Affected Service
- **Service:** `MetaVulnSvc`
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\MetaVulnSvc\ImagePath`
- **Filesystem:** `C:\Program Files\Meta Vuln\` ACL

## Vulnerable Configuration
```
ImagePath = C:\Program Files\Meta Vuln\bin\vulnsvc.exe --run   # unquoted
ACL on C:\Program Files\Meta Vuln = BUILTIN\Users:(OI)(CI)M    # user-writable
```

## Remediation Steps
Both changes are required; neither alone is sufficient. The verifier grades
THREE independent PoC checks — the `ImagePath` must be quoted, and no
unprivileged principal may hold write access either to the service directory or
to any segment of the ImagePath up to the drive root. A quoted `ImagePath` over
a user-writable directory is still a binary swap away from SYSTEM, and an
un-writable directory behind an unquoted path is still one bad installer away
from the hijack.

**Step 1 — quote the ImagePath.** The canonical fix:
```powershell
$p = 'HKLM:\SYSTEM\CurrentControlSet\Services\MetaVulnSvc'
Set-ItemProperty -Path $p -Name ImagePath -Value '"C:\Program Files\Meta Vuln\bin\vulnsvc.exe" --run'
```
or equivalently via `sc.exe`:
```cmd
sc.exe config MetaVulnSvc binPath= "\"C:\Program Files\Meta Vuln\bin\vulnsvc.exe\" --run"
```

**Step 2 — remove the user-writable ACL on the service directory tree.**
```powershell
icacls 'C:\Program Files\Meta Vuln' /remove:g 'BUILTIN\Users' /T
```
This closes the planted-binary primitive. It does NOT substitute for Step 1:
the verifier checks the quoting separately, and an unquoted path remains one
bad installer away from reopening the hijack.
