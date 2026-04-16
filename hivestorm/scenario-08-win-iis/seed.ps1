# Hivestorm HS21 scenario-08 — Windows Server-Core + IIS + PHP misconfigs.
$ErrorActionPreference = "Stop"

$roles = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin           = $roles.admin_user
$adminPw         = $roles.admin_weak_password
$rogue           = $roles.rogue_admin
$schtaskName     = $roles.schtask_name
$cryptominerPath = $roles.cryptominer_path
$phpinfoPath     = $roles.phpinfo_path

# ---- users --------------------------------------------------------------------
$securePw = ConvertTo-SecureString $adminPw -AsPlainText -Force
New-LocalUser -Name $admin -Password $securePw -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group "Administrators" -Member $admin

$rogueSecure = ConvertTo-SecureString "changeme" -AsPlainText -Force
New-LocalUser -Name $rogue -Password $rogueSecure -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group "Administrators" -Member $rogue

# ---- password policy ---------------------------------------------------------
net accounts /minpwlen:0 | Out-Null
net accounts /maxpwage:unlimited | Out-Null

# ---- audit policy gutted -----------------------------------------------------
auditpol.exe /set /subcategory:"User Account Management" /success:disable /failure:disable | Out-Null
auditpol.exe /set /subcategory:"System Integrity"        /success:disable /failure:disable | Out-Null

# ---- IIS: default site SSL not required --------------------------------------
# applicationHost.config lives here on Server-Core IIS image.
Import-Module WebAdministration
# Ensure the site exists (default "Default Web Site").
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
    -Filter "system.webServer/security/access" -Name "sslFlags" -Value "None" `
    -Location "Default Web Site" -ErrorAction SilentlyContinue

# ---- phpinfo.php dropped ------------------------------------------------------
$phpDir = Split-Path $phpinfoPath
New-Item -ItemType Directory -Force -Path $phpDir | Out-Null
Set-Content -Path $phpinfoPath -Value "<?php phpinfo(); ?>"

# ---- php.ini mocked under C:\PHP with display_errors=On ----------------------
New-Item -ItemType Directory -Force -Path "C:\PHP" | Out-Null
@"
; Hivestorm-planted mock php.ini (PHP interpreter not actually installed).
display_errors = On
expose_php     = On
allow_url_include = On
"@ | Set-Content -Path "C:\PHP\php.ini"

# ---- cryptominer binary + scheduled task -------------------------------------
$minerDir = Split-Path $cryptominerPath
New-Item -ItemType Directory -Force -Path $minerDir | Out-Null
Copy-Item C:\Windows\System32\cmd.exe $cryptominerPath -Force

$action  = New-ScheduledTaskAction -Execute $cryptominerPath -Argument "/c miner"
$trigger = New-ScheduledTaskTrigger -AtStartup
$princ   = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName $schtaskName -Action $action -Trigger $trigger `
    -Principal $princ -Force | Out-Null

# ---- Remote Registry: Automatic ----------------------------------------------
Set-Service -Name RemoteRegistry -StartupType Automatic -ErrorAction SilentlyContinue

# ---- AutoPlay enabled --------------------------------------------------------
$auto = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
New-Item -Path $auto -Force | Out-Null
Set-ItemProperty -Path $auto -Name NoDriveTypeAutoRun -Value 0 -Type DWord
