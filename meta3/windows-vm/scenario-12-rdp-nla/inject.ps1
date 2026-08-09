# meta3/windows-vm/scenario-12-rdp-nla/inject.ps1
# Introduces the vuln on the hardened baseline: disable Network Level
# Authentication on the RDP-Tcp listener (UserAuthentication=0, SecurityLayer=1)
# so a live X.224 negotiation now grants PROTOCOL_RDP -- Standard RDP Security
# with no CredSSP in front of it. RDP itself stays enabled
# (fDenyTSConnections=0) and 3389 keeps listening.
#
# Runs INSIDE the VM (via AutomatedLab Invoke-LabCommand, or the SSH bridge).
#
# THERE IS DELIBERATELY NO Restart-Service HERE, AND THAT IS A FIX.
# The previous revision ended with `Restart-Service -Name TermService -Force`
# under $ErrorActionPreference = 'Stop'. On META3WIN that FAILS, and it failed
# on a clean `./run-scenario.sh 12` immediately after a baseline restore:
#     Service 'Remote Desktop Services (TermService)' stop failed.
#     ... StopServiceFailed,Microsoft.PowerShell.Commands.RestartServiceCommand
# which is terminating here, so inject.ps1 died on its last line and the driver
# never reached its readiness gate. (`Stop-Service TermService -Force` on its own
# returns in ~270 ms; it is Restart-Service's stop-and-wait that does not survive
# a freshly restored VM, and the same command succeeds a couple of minutes
# later. A step that works only sometimes is worse than no step.)
#
# The restart was never needed: the RDP-Tcp security policy is read PER
# CONNECTION, not cached at service start. MEASURED on META3WIN with no restart
# of any kind between the three transitions, probing the live listener after
# each registry write:
#     UA=1 SL=2  -> RDP_NEG_FAILURE, HYBRID_REQUIRED_BY_SERVER
#     UA=0 SL=1  -> RDP_NEG_RSP, selectedProtocol = PROTOCOL_RDP
#     UA=1 SL=2  -> RDP_NEG_FAILURE, HYBRID_REQUIRED_BY_SERVER
# So the write alone arms the vulnerability, in both directions, immediately.

$ErrorActionPreference = 'Stop'

$rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$tsBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

function Wait-Rdp3389Listening {
    param([int] $TimeoutSeconds = 120)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue) { return $true }
        Start-Sleep -Seconds 3
    }
    return $false
}

Write-Host "[inject-12] disabling Network Level Authentication on RDP-Tcp"

# NLA off, security layer down to "negotiate" so plain RDP is acceptable.
Set-ItemProperty -Path $rdpTcp -Name 'UserAuthentication' -Value 0 -Type DWord
Set-ItemProperty -Path $rdpTcp -Name 'SecurityLayer'      -Value 1 -Type DWord
# Keep RDP enabled so the listener stays up and 3389 keeps listening.
Set-ItemProperty -Path $tsBase -Name 'fDenyTSConnections' -Value 0 -Type DWord

# The listener must be up for the vulnerability to exist at all.
if ((Get-Service -Name TermService).Status -ne 'Running') { Start-Service -Name TermService }
if (-not (Wait-Rdp3389Listening)) {
    throw "[inject-12] TCP/3389 is not listening - refusing to hand back a half-injected host"
}

# --- refuse to return unless the vulnerability is actually LIVE on the wire ---
#
# Registry values are not evidence: they are just what this script wrote a
# moment ago. The scenario is armed only if the running listener really does
# grant PROTOCOL_RDP, so ask it. rdp_nla_probe.ps1 is staged in this same
# directory and exits 0 for VULNERABLE, 2 for REMEDIATED, 3 for INDETERMINATE.
$probe = Join-Path $PSScriptRoot 'rdp_nla_probe.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -TargetHost 127.0.0.1 -Port 3389
$rc = $LASTEXITCODE
if ($rc -ne 0) {
    throw "[inject-12] the live listener did NOT accept plain RDP (probe rc=$rc) - inject did not introduce the vulnerability"
}

$ua = (Get-ItemProperty -Path $rdpTcp -Name 'UserAuthentication').UserAuthentication
$sl = (Get-ItemProperty -Path $rdpTcp -Name 'SecurityLayer').SecurityLayer
Write-Host "[inject-12] UserAuthentication=$ua; SecurityLayer=$sl; 3389 listening; plain RDP accepted on the wire - LIVE-vulnerable"
