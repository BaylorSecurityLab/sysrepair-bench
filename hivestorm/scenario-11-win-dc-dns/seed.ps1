# Hivestorm HS23 scenario-11 — Server-Core + DC/DNS-style misconfigs
# planted in the registry. No actual AD DS / DNS Server install.
$ErrorActionPreference = "Stop"

$roles = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin   = $roles.admin_user
$adminPw = $roles.admin_weak_password
$rogue   = $roles.rogue_admin

# ---- users -------------------------------------------------------------------
$securePw = ConvertTo-SecureString $adminPw -AsPlainText -Force
New-LocalUser -Name $admin -Password $securePw -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group "Administrators" -Member $admin

$rogueSecure = ConvertTo-SecureString "Changeme!1" -AsPlainText -Force
New-LocalUser -Name $rogue -Password $rogueSecure -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group "Administrators" -Member $rogue

# ---- helper ------------------------------------------------------------------
function PlantDword($path, $name, $value) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord
}

# ---- LDAP server signing NOT required (LDAPServerIntegrity = 1) -------------
PlantDword "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
           "LDAPServerIntegrity" 1

# ---- MS network client NOT digitally signing --------------------------------
PlantDword "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
           "RequireSecuritySignature" 0

# ---- Kerberos: weak encryption types (DES + RC4 enabled) --------------------
# Bitmask: 0x1=DES_CBC_CRC, 0x2=DES_CBC_MD5, 0x4=RC4_HMAC_MD5,
#          0x8=AES128, 0x10=AES256. 0x1F = all-on (intentionally weak).
PlantDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" `
           "SupportedEncryptionTypes" 0x1F

# ---- LLMNR enabled (DNS multicast on) ---------------------------------------
PlantDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
           "EnableMulticast" 1

# ---- DNS Server: cache pollution NOT secured + event-log level zero ---------
PlantDword "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" `
           "SecureResponses" 0
PlantDword "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" `
           "EventLogLevel" 0

# ---- Credential UI enumerates Administrators --------------------------------
PlantDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" `
           "EnumerateAdministrators" 1

# ---- Print Spooler running (Automatic) --------------------------------------
# Server-Core containers ship with the Print-Server feature stripped and no
# installation media bundled (Install-WindowsFeature fails with 0x800f081f).
# Register a Spooler service entry directly via sc.exe — that writes the SCM
# registry hive at HKLM:\SYSTEM\CurrentControlSet\Services\Spooler, which is
# all Get-Service / Set-Service read. The defender's remediation (disable the
# service = write Start=4) is purely a registry op, so the binary never has
# to exist for the check to score faithfully.
if (-not (Get-Service -Name Spooler -ErrorAction SilentlyContinue)) {
    sc.exe create Spooler binPath= 'C:\Windows\System32\spoolsv.exe' `
        start= auto DisplayName= 'Print Spooler' | Out-Null
}
Set-Service -Name Spooler -StartupType Automatic -ErrorAction SilentlyContinue

# ---- WinRM Automatic --------------------------------------------------------
Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue

# ---- audit User Account Management gutted -----------------------------------
auditpol.exe /set /subcategory:"User Account Management" /success:disable /failure:disable | Out-Null
