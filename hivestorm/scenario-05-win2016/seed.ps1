# Hivestorm HS20 scenario-05 — Windows Server 2016 misconfigurations.
$ErrorActionPreference = "Stop"

$roles = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin       = $roles.admin_user
$adminPw     = $roles.admin_weak_password
$rogue       = $roles.rogue_admin
$schtaskName = $roles.schtask_name
$bkpOp       = $roles.rogue_backup_operator
$trojan      = $roles.trojan_path

# ---- users --------------------------------------------------------------------
$securePw = ConvertTo-SecureString $adminPw -AsPlainText -Force
New-LocalUser -Name $admin -Password $securePw -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group "Administrators" -Member $admin

$rogueSecure = ConvertTo-SecureString "changeme" -AsPlainText -Force
New-LocalUser -Name $rogue -Password $rogueSecure -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group "Administrators" -Member $rogue

# Rogue Backup Operators member (separate user).
if ($bkpOp -ne $rogue) {
    New-LocalUser -Name $bkpOp -Password $rogueSecure -PasswordNeverExpires -AccountNeverExpires | Out-Null
}
Add-LocalGroupMember -Group "Backup Operators" -Member $bkpOp -ErrorAction SilentlyContinue

# ---- LLMNR enabled (set EnableMulticast=1) -----------------------------------
$dns = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
New-Item -Path $dns -Force | Out-Null
Set-ItemProperty -Path $dns -Name EnableMulticast -Value 1 -Type DWord

# ---- SMBv1 server + client ---------------------------------------------------
$smbSrv = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-ItemProperty -Path $smbSrv -Name SMB1 -Value 1 -Type DWord
$mrx = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
New-Item -Path $mrx -Force | Out-Null
Set-ItemProperty -Path $mrx -Name Start -Value 2 -Type DWord

# ---- RestrictAnonymous=0 -----------------------------------------------------
$lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsa -Name RestrictAnonymous -Value 0 -Type DWord

# ---- EventLog service start disabled -----------------------------------------
$el = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog"
Set-ItemProperty -Path $el -Name Start -Value 4 -Type DWord

# ---- Telnet-Server registered (feature-installed proxy) ----------------------
$tln = "HKLM:\SYSTEM\CurrentControlSet\Services\TlntSvr"
New-Item -Path $tln -Force | Out-Null
Set-ItemProperty -Path $tln -Name Start -Value 2 -Type DWord
Set-ItemProperty -Path $tln -Name ImagePath -Value "C:\Windows\System32\tlntsvr.exe" -Type String

# ---- Trojan file -------------------------------------------------------------
$trojanDir = Split-Path $trojan
New-Item -ItemType Directory -Force -Path $trojanDir | Out-Null
Copy-Item C:\Windows\System32\cmd.exe $trojan -Force

# ---- AT-style scheduled task running trojan ----------------------------------
schtasks.exe /Create /TN $schtaskName /SC ONSTART /RU SYSTEM `
    /TR "`"$trojan`" /c whoami" /F | Out-Null
