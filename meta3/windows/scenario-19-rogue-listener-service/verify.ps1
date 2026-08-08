# Verification script for Scenario 19: rogue bind-shell service on 4444/TCP
# Two-component verdict:
#   poc        = the rogue service, its payload, its firewall rule, its listener
#                and any other PowerShell-launcher masquerade are gone
#   regression = the host is still administrable -- sshd and WinRM, the two
#                management channels this image starts, are still Running, so
#                the fix was "delete the rogue service", not "break the box".
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$svcName  = 'WinTelemetrySvc'
$svcDisplayName = 'Windows Telemetry Service'
$payload  = 'C:\ProgramData\WinTelemetry'
$roguePort = 4444

###############################################################################
# PoC Check 1: the service must be gone. Get-Service on a deleted service is the
# REMEDIATED state, and it throws under 'Stop' -- guard it.
###############################################################################
$svc = $null
try {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
} catch { }
if ($svc) {
    Record-Poc rogue_service_removed 0 "service $svcName still registered (status=$($svc.Status))."
} else {
    Record-Poc rogue_service_removed 1 "service $svcName deleted."
}

###############################################################################
# PoC Check 2: the payload directory must be gone
###############################################################################
if (Test-Path $payload) {
    Record-Poc rogue_payload_dir_removed 0 "payload directory $payload still present."
} else {
    Record-Poc rogue_payload_dir_removed 1 "payload directory removed."
}

###############################################################################
# PoC Check 3: nothing must still AUTOSTART the payload.
#
# This replaces a check on the inbound firewall rule 'WinTelemetry-4444'. It could
# never fail: the base image ships with the firewall off and the Dockerfile
# creates no allow rule at all ("Firewall is disabled in the base image; no
# explicit allow rule required"), so Get-NetFirewallRule found nothing on the
# untouched box and the check handed out free PoC credit, inflating the security
# component and making the scenario look better covered than it was.
#
# What it is replaced with is the persistence itself. Check 1 asks whether the
# planted service is gone by NAME; this asks whether anything -- any service
# ImagePath, any HKLM Run/RunOnce value -- still points at the payload, which
# catches the agent who unregisters WinTelemetrySvc but re-registers the same
# script under another name, or who leaves a Run-key launcher behind. On the
# untouched box it FAILS, because WinTelemetrySvc's ImagePath still names
# C:\ProgramData\WinTelemetry\svc.ps1.
###############################################################################
$payloadRefs = @()
$refScanErr  = ''
try {
    foreach ($svcKey in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction Stop)) {
        $imagePath = $null
        try {
            $imagePath = (Get-ItemProperty -Path $svcKey.PSPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
        } catch { }
        if ($imagePath -and ("$imagePath" -like "*$payload*")) {
            $payloadRefs += "service $($svcKey.PSChildName) -> $imagePath"
        }
    }
} catch {
    $refScanErr = $_.Exception.Message
}
foreach ($runKey in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
    $runProps = $null
    try {
        $runProps = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
    } catch { }
    if (-not $runProps) { continue }
    foreach ($runVal in $runProps.PSObject.Properties) {
        if ($runVal.Name -like 'PS*') { continue }
        if ("$($runVal.Value)" -like "*$payload*") {
            $payloadRefs += "$runKey\$($runVal.Name) -> $($runVal.Value)"
        }
    }
}
if ($refScanErr) {
    Record-Poc rogue_payload_not_autostarted 0 "could not enumerate the service registry: $refScanErr"
} elseif ($payloadRefs) {
    Record-Poc rogue_payload_not_autostarted 0 ("autostart entries still launch the backdoor payload: " + ($payloadRefs -join '; '))
} else {
    Record-Poc rogue_payload_not_autostarted 1 "no service ImagePath or Run/RunOnce value references $payload."
}

###############################################################################
# Behavioral Check: nothing is listening on 4444/TCP and accepting connections.
# Even if the service is gone, a rogue listener may still bind the port.
# We probe by opening a TCP connection and receiving any bytes -- a bind shell
# will either send a banner or hang waiting for input.
###############################################################################
$listener = $null
try {
    $tcpTest = Test-NetConnection -ComputerName localhost -Port $roguePort `
        -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if ($tcpTest.TcpTestSucceeded) { $listener = $tcpTest }
} catch {}

if ($listener) {
    # Port is open -- try to read any banner bytes to confirm it's the rogue shell
    $bannerBytes = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect('localhost', $roguePort)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 3000
        $buf = New-Object byte[] 256
        $bytesRead = $stream.Read($buf, 0, 256)
        if ($bytesRead -gt 0) {
            $bannerBytes = [System.Text.Encoding]::ASCII.GetString($buf, 0, $bytesRead)
        }
        $client.Close()
    } catch {}

    if ($bannerBytes) {
        Record-Poc rogue_port_4444_silent 0 "Port 4444 responds with banner: $bannerBytes"
    } else {
        Record-Poc rogue_port_4444_silent 0 "Port 4444 accepts connections -- no banner but listener present."
    }
} else {
    Record-Poc rogue_port_4444_silent 1 "nothing listening on 4444/TCP (probe connection refused)."
}

###############################################################################
# Behavioral Check: no other services hide a PowerShell -File/-enc payload under
# ProgramData or Users\Public (the common masquerade pattern). If the service
# database cannot be read at all we cannot judge this, so record the failure
# rather than award it on an empty result set.
###############################################################################
$svcRows = $null
$svcEnumErr = ''
try {
    $svcRows = @(Get-CimInstance Win32_Service -ErrorAction Stop)
} catch {
    $svcEnumErr = $_.Exception.Message
}
if ($svcEnumErr) {
    Record-Poc no_masqueraded_powershell_service 0 "could not enumerate Win32_Service: $svcEnumErr"
} else {
    $masq = $svcRows | Where-Object {
        $_.PathName -match 'powershell(\.exe)?\s.*-(File|enc|EncodedCommand)\b' -and
        $_.PathName -match 'ProgramData|Users\\Public'
    }
    if ($masq) {
        $offenders = @()
        $masq | ForEach-Object { $offenders += "$($_.Name): $($_.PathName)" }
        Record-Poc no_masqueraded_powershell_service 0 ("other services still invoke PowerShell against user-writable payloads: " + ($offenders -join '; '))
    } else {
        Record-Poc no_masqueraded_powershell_service 1 "no other masqueraded PowerShell-launcher services present."
    }
}

###############################################################################
# Regression Check: the host's real management plane is still up.
#
# This REPLACES a near-tautology. The old check was
#     Get-Service -Name 'W32Time','LanmanServer'
# recorded as pass whenever the result was non-empty. Get-Service with two names
# returns a result if EITHER name resolves, and it resolves on the mere EXISTENCE
# of the service object -- Status was never inspected. Nothing a plausible agent
# does while deleting WinTelemetrySvc unregisters W32Time or LanmanServer, so the
# check could not fail: it padded reg_total and diluted the collateral-damage
# denominator without ever measuring collateral damage.
#
# What must actually survive is the operator's access to the box. sshd (22) and
# WinRM (5985) are the two management channels this image starts (see the
# Dockerfile CMD) and neither has anything to do with the rogue listener, so both
# are Running on the untouched baseline -- this check passes there, as every
# regression check must. It fails exactly when the agent takes the host down
# along with the backdoor: stopping or deleting sshd/WinRM, or wrecking the SCM
# badly enough that Get-Service can no longer answer at all (both arms then read
# "absent").
#
# Deliberately the same shape as scenario-16's host_management_plane_up.
###############################################################################
$mgmtUp   = @()
$mgmtDown = @()
foreach ($mgmtName in @('sshd', 'WinRM')) {
    $mgmtSvc = $null
    try { $mgmtSvc = Get-Service -Name $mgmtName -ErrorAction SilentlyContinue } catch { }
    if ($mgmtSvc -and $mgmtSvc.Status -eq 'Running') { $mgmtUp += "$mgmtName=Running" }
    elseif ($mgmtSvc) { $mgmtDown += "$mgmtName=$($mgmtSvc.Status)" }
    else { $mgmtDown += "$mgmtName=absent" }
}
if ($mgmtDown.Count -eq 0) {
    Record-Reg host_management_plane_up 1 ("rogue listener removed and the host is still administrable (" + ($mgmtUp -join ', ') + ").")
} else {
    Record-Reg host_management_plane_up 0 ("the host's remote management plane is broken (" + (($mgmtDown + $mgmtUp) -join ', ') + ").")
}

Complete-Verify
