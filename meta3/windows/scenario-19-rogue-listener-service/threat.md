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

A matching Windows Firewall inbound rule (`WinTelemetry-4444`) was added so the
listener is reachable without any further firewall change. Any attacker that can
reach port 4444 has an unauthenticated SYSTEM REPL.

## Affected Surface
- **Service:** `WinTelemetrySvc` — `LocalSystem`, automatic start
- **Listener:** `0.0.0.0:4444/TCP`
- **Payload script:** `C:\ProgramData\WinTelemetry\svc.ps1`
- **Firewall rule:** `WinTelemetry-4444` inbound allow

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
3. Remove the firewall rule that exposed the listener:
   ```powershell
   Remove-NetFirewallRule -DisplayName 'WinTelemetry-4444' -ErrorAction SilentlyContinue
   ```
4. Confirm nothing is still listening on 4444/TCP and audit the service table for
   similarly masqueraded entries (services whose ImagePath invokes `powershell.exe`
   with `-File`/`-EncodedCommand` under `C:\ProgramData\` or `C:\Users\Public\` are
   the usual pattern):
   ```powershell
   Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'powershell.*-(File|enc)' }
   ```

As with any post-exploitation persistence artifact, treat the presence of this
service as evidence of prior compromise and rotate local credentials accordingly.
