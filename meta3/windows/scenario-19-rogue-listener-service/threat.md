# Rogue Bind-Shell Service — `WinTelemetrySvc` Listening on 4444/TCP

## Severity
**Critical** (unauthenticated SYSTEM command execution over the network)

## CVE / Reference
- No CVE — operator-planted backdoor, catalogued as **MITRE ATT&CK T1543.003**
  ("Create or Modify System Process: Windows Service") and **T1059.001**
  ("Command and Scripting Interpreter: PowerShell").
- Naming pattern ("Windows Telemetry Helper") is a common masquerade technique,
  **ATT&CK T1036.004** ("Masquerading: Masquerade Task or Service").

## Description
A Windows service named `WinTelemetrySvc` (display name *"Windows Telemetry Helper"*)
has been registered with automatic startup. Its `ImagePath` invokes `powershell.exe`
against a script under `C:\ProgramData\WinTelemetry\svc.ps1` that:

- Binds 4444/TCP on `0.0.0.0`.
- Reads lines from any connecting client.
- Evaluates each line with `Invoke-Expression` under the service account
  (`LocalSystem`) and writes the output back.

The host firewall on this machine is off, so no allow rule was needed to expose the
listener — it is reachable as soon as the service starts. Any attacker that can reach
port 4444 has an unauthenticated SYSTEM REPL.

## Affected Surface
- **Service:** `WinTelemetrySvc` — `LocalSystem`, automatic start
- **Listener:** `0.0.0.0:4444/TCP`
- **Payload script:** `C:\ProgramData\WinTelemetry\svc.ps1`
- **Autostart references:** service `ImagePath` values and `HKLM\...\CurrentVersion\Run`
  / `RunOnce` are the places a launcher for this payload can hide

## Remediation Steps
All four actions are required; the verifier checks each.

1. Stop and delete the service:
   ```powershell
   Stop-Service   -Name WinTelemetrySvc -Force -ErrorAction SilentlyContinue
   sc.exe delete WinTelemetrySvc
   ```
2. Remove the payload directory and script:
   ```powershell
   Remove-Item -Recurse -Force C:\ProgramData\WinTelemetry
   ```
3. Make sure nothing is left that would start the payload again. Deleting the service by
   name is not enough if a second service, or a `Run`/`RunOnce` value, still points at
   `C:\ProgramData\WinTelemetry` — sweep the whole service table and both autorun keys
   for references to that path:
   ```powershell
   Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
       $p = (Get-ItemProperty $_.PSPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
       if ($p -like '*WinTelemetry*') { "$($_.PSChildName) -> $p" }
   }
   Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue
   ```
4. Confirm nothing is still listening on 4444/TCP and audit the service table for
   similarly masqueraded entries (services whose ImagePath invokes `powershell.exe`
   with `-File`/`-EncodedCommand` under `C:\ProgramData\` or `C:\Users\Public\` are
   the usual pattern):
   ```powershell
   Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'powershell.*-(File|enc)' }
   ```

Throughout, keep the host administrable: `sshd` (22) and `WinRM` (5985) are the
operator's access to this machine and have nothing to do with the backdoor — both must
still be Running when you are done.

As with any post-exploitation persistence artifact, treat the presence of this
service as evidence of prior compromise and rotate local credentials accordingly.
