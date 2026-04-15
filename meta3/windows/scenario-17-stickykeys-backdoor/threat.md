# Sticky Keys Backdoor — `sethc.exe` Replaced with `cmd.exe`

## Severity
**Critical** (pre-auth SYSTEM shell at the logon screen)

## CVE / Reference
- No CVE — this is a classic post-exploitation persistence technique catalogued as
  **MITRE ATT&CK T1546.008** ("Event Triggered Execution: Accessibility Features").
- Routinely used alongside `utilman.exe`, `osk.exe`, `narrator.exe`, and
  `magnify.exe` — any of the accessibility binaries that winlogon will launch from
  a locked desktop.

## Description
Pressing Shift five times at the logon screen triggers `C:\Windows\System32\sethc.exe`
(the Sticky Keys handler) under the **winlogon** session, which runs as
`NT AUTHORITY\SYSTEM`. If `sethc.exe` has been replaced with `cmd.exe`, an attacker
who can reach the console or an RDP pre-auth banner gets an interactive SYSTEM shell
without supplying a single credential.

Typical deployment footprint:
- `sethc.exe` file hash matches `cmd.exe` rather than the legitimate accessibility
  binary.
- A backup copy exists at `sethc.exe.bak` (operator's own safety net).
- The file owner is `BUILTIN\Administrators` rather than `TrustedInstaller`.

## Affected Surface
- **Binary:** `C:\Windows\System32\sethc.exe`
- **Trigger:** Shift × 5 at logon / lock screen (local console or RDP banner).
- **Runs as:** `NT AUTHORITY\SYSTEM`.

## Remediation Steps
1. Restore the legitimate Sticky Keys handler from the original Windows image. The
   fastest in-place repair uses SFC to pull a known-good copy from the component
   store:
   ```powershell
   sfc /scanfile=C:\Windows\System32\sethc.exe
   ```
   If SFC reports "could not repair," pull `sethc.exe` from a clean Server Core
   ltsc2019 image and copy it back.
2. Remove the `sethc.exe.bak` artifact (operator-left backup):
   ```powershell
   Remove-Item C:\Windows\System32\sethc.exe.bak -Force -ErrorAction SilentlyContinue
   ```
3. Restore TrustedInstaller ownership so the file cannot be silently replaced again:
   ```powershell
   icacls C:\Windows\System32\sethc.exe /setowner 'NT SERVICE\TrustedInstaller'
   icacls C:\Windows\System32\sethc.exe /inheritance:r /grant:r 'NT SERVICE\TrustedInstaller:(F)' 'BUILTIN\Administrators:(RX)' 'NT AUTHORITY\SYSTEM:(RX)' 'BUILTIN\Users:(RX)'
   ```
4. Apply the same treatment to the other accessibility binaries (`utilman.exe`,
   `osk.exe`, `narrator.exe`, `magnify.exe`) — swapping any of them is the same attack.
5. Audit: the Sticky Keys bypass is an operator artifact, not a software bug. Treat
   its presence as evidence of prior compromise and rotate local admin credentials.
