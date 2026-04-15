# Scheduled Task Backdoor — Hidden SYSTEM Task Launching Payload from `C:\Users\Public`

## Severity
**High** (persistent SYSTEM-level code execution)

## CVE / Reference
- No CVE — operator-planted persistence, catalogued as **MITRE ATT&CK T1053.005**
  ("Scheduled Task/Job: Scheduled Task").
- Payload staging directory corresponds to **T1074** ("Data Staged: Local Data
  Staging").

## Description
A scheduled task named `Windows Update Assistant` has been registered under
`\Microsoft\Windows\UpdateOrchestrator\` — a path that blends in with real Microsoft
tasks — with the following properties:

- Runs as `NT AUTHORITY\SYSTEM` at highest integrity.
- Triggers at every user logon **and** every hour, indefinitely.
- Marked `Hidden`, so `schtasks /query` without `/v` omits it in some views.
- Executes a PowerShell script at `C:\Users\Public\Updater\updater.ps1` — a
  world-writable staging directory (BUILTIN\Users have Modify).

The immediate payload only writes a heartbeat log, but the combination of a
SYSTEM-level execution primitive plus a user-writable payload file means any local
user can overwrite `updater.ps1` with arbitrary code and wait for the next hourly
trigger to escalate to SYSTEM.

## Affected Surface
- **Task:** `\Microsoft\Windows\UpdateOrchestrator\Windows Update Assistant`
- **Payload file:** `C:\Users\Public\Updater\updater.ps1`
- **Payload directory ACL:** `C:\Users\Public\Updater` grants `BUILTIN\Users:(OI)(CI)M`

## Remediation Steps
All three actions are required; the verifier checks each.

1. Unregister the rogue task:
   ```powershell
   Unregister-ScheduledTask -TaskName 'Windows Update Assistant' `
     -TaskPath '\Microsoft\Windows\UpdateOrchestrator\' -Confirm:$false
   ```
2. Remove the staging directory and payload:
   ```powershell
   Remove-Item -Recurse -Force C:\Users\Public\Updater
   ```
3. Audit scheduled tasks for other operator-planted entries — anything under
   `\Microsoft\Windows\` that is not signed by Microsoft, runs as SYSTEM, and points
   at a user-writable path is suspect:
   ```powershell
   Get-ScheduledTask | Where-Object {
       $_.Principal.UserId -eq 'SYSTEM' -and
       ($_.Actions.Execute -match 'Users\\Public|ProgramData|Temp')
   }
   ```
4. As with all post-exploitation persistence, treat its presence as evidence of
   prior compromise — rotate local admin credentials and review the host's event log
   for the initial foothold.
