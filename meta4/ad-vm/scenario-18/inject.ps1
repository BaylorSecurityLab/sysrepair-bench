$ErrorActionPreference = 'Stop'

$sysvolPath = '\\corp-dc01\SYSVOL\corp.local\Policies\{LAB-GPP-18}\Machine\Preferences\Drives'
New-Item -ItemType Directory -Path $sysvolPath -Force | Out-Null

# This is the cpassword for the literal string "Summer24" encrypted with
# Microsoft's published GPP AES key (publicly documented in MS14-025
# advisory). Any modern PoC tool can decrypt it -- we use the canonical
# test-vector value to make the lab deterministic.
$cpassword = 'j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw'

@"
<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">
  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="S:" status="S:" image="2"
    changed="2024-09-01 00:00:00" uid="{99999999-9999-9999-9999-999999999999}">
    <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE"
      userName="corp\svc_sql" cpassword="$cpassword"
      path="\\corp-dc01\Shared" label="Shared" persistent="1"
      useLetter="1" letter="S"/>
  </Drive>
</Drives>
"@ | Out-File -FilePath (Join-Path $sysvolPath 'Drives.xml') -Encoding utf8 -Force

Write-Host "[inject-18] Legacy GPP Drives.xml with cpassword planted in SYSVOL"
