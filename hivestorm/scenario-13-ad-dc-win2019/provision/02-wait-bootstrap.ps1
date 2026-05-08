$ErrorActionPreference = "Stop"

# By the time this provisioner connects via WinRM, the SYSTEM bootstrap task
# has either:
#   - already finished (marker present, OPS\vagrant in DA → auth works), or
#   - still running mid-DCPROMO (auth as `vagrant` may flap). Vagrant's
#     winrm.retry_limit covers the connect-side gap; once we get a session,
#     we just poll for the marker every 30s.
$marker = "C:\hs13-setup\BOOTSTRAP_COMPLETE"
$deadline = (Get-Date).AddMinutes(25)
while ((Get-Date) -lt $deadline) {
    if (Test-Path $marker) { break }
    Start-Sleep -Seconds 30
}
if (-not (Test-Path $marker)) {
    if (Test-Path "C:\hs13-setup\bootstrap.log") {
        Write-Host "--- bootstrap.log tail ---"
        Get-Content "C:\hs13-setup\bootstrap.log" -Tail 100 | Write-Host
    }
    throw "hs13-bootstrap chain did not finish within 25 min"
}
Write-Host "[02-wait-bootstrap] BOOTSTRAP_COMPLETE marker found"
