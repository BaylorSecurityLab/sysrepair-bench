# Sticky Keys Backdoor — IFEO `Debugger` Hijack on `sethc.exe` / `utilman.exe`

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
`NT AUTHORITY\SYSTEM`. If that launch can be redirected to a shell, an attacker who can
reach the console or an RDP pre-auth banner gets an interactive SYSTEM shell without
supplying a single credential.

The technique has two variants. The classic one overwrites the accessibility binary
itself with a copy of `cmd.exe`. The variant deployed on **this** host is the registry
form: an **Image File Execution Options (IFEO)** `Debugger` value has been planted for
`sethc.exe` and `utilman.exe`. IFEO is the supported mechanism for attaching a debugger
to a named image — when a `Debugger` value is present, the loader launches *that* program
with the original image as its argument instead of running the image. Pointing it at
`cmd.exe` produces the same pre-auth SYSTEM shell with the on-disk binaries left
byte-for-byte genuine, so file hashing and `sfc` will report nothing wrong.

This is Server Core, which ships no accessibility executables at all — there is no
`sethc.exe` on disk to inspect. The hijack lives entirely in the registry and would fire
the moment this configuration reached a Desktop Experience or RDP-enabled host.

Typical deployment footprint:
- An IFEO subkey named after an accessibility executable, carrying a `Debugger` value
  that points at `cmd.exe` (or `powershell.exe`).
- Applied to more than one target — `sethc.exe` and `utilman.exe` are the usual pair,
  with `osk.exe`, `Magnify.exe`, `Narrator.exe` and `DisplaySwitch.exe` equally viable.
- On hosts where the binaries do exist, the file-swap variant instead: the accessibility
  binary's hash matches `cmd.exe`, and its owner is `BUILTIN\Administrators` rather than
  `NT SERVICE\TrustedInstaller`.

## Affected Surface
- **Registry:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>`
  → `Debugger` (REG_SZ)
- **Targets:** `sethc.exe`, `utilman.exe`, `osk.exe`, `Magnify.exe`, `Narrator.exe`,
  `DisplaySwitch.exe`
- **Trigger:** Shift × 5 (or the Ease-of-Access button) at logon / lock screen, local
  console or RDP banner.
- **Runs as:** `NT AUTHORITY\SYSTEM`.

## Remediation Steps
1. Enumerate the IFEO hive and find every subkey that carries a `Debugger` value:
   ```powershell
   $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
   Get-ChildItem $ifeo | ForEach-Object {
       $d = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
       if ($d) { "$($_.PSChildName) -> $d" }
   }
   ```
2. Remove the hijack. Delete the `Debugger` **value** (or the per-image subkey the
   intruder created) for each accessibility executable — do **not** delete the
   `Image File Execution Options` key itself. That hive is the supported mechanism for
   attaching a debugger and for per-image AppCompat settings; destroying it is collateral
   damage, not remediation:
   ```powershell
   Remove-ItemProperty -Path "$ifeo\sethc.exe" -Name Debugger -ErrorAction SilentlyContinue
   ```
3. Check the file-swap variant too, on any host where the accessibility binaries exist:
   an accessibility binary whose SHA256 equals `cmd.exe` or `powershell.exe` has been
   replaced. Restore it from the component store and put ownership back:
   ```powershell
   sfc /scanfile=C:\Windows\System32\sethc.exe
   icacls C:\Windows\System32\sethc.exe /setowner 'NT SERVICE\TrustedInstaller'
   ```
4. Apply both checks to every accessibility executable, not just `sethc.exe` — hijacking
   any of them is the same attack.
5. Audit: the Sticky Keys bypass is an operator artifact, not a software bug. Treat
   its presence as evidence of prior compromise and rotate local admin credentials.
