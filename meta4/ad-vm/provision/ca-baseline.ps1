# meta4/ad-vm/provision/ca-baseline.ps1
# Joins corp.local as member server, installs Enterprise CA role, installs Cert Authority,
# leaves web enrollment disabled and only default templates published.

$ErrorActionPreference = 'Stop'

$domainName   = 'corp.local'
$domainUser   = 'CORP\Administrator'
$domainPass   = ConvertTo-SecureString 'Password1!' -AsPlainText -Force
$domainCred   = New-Object System.Management.Automation.PSCredential($domainUser, $domainPass)
$caCommonName = 'corp-ca01-CA'

# --- 0. DNS: point at DC on the private_network NIC (10.20.30.0/24) ---
$privateAddr = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
  Where-Object IPAddress -like '10.20.30.*' |
  Select-Object -First 1
if (-not $privateAddr) {
    throw '[ca-baseline] no NIC found on 10.20.30.0/24; cannot set domain DNS'
}
Set-DnsClientServerAddress -InterfaceIndex $privateAddr.InterfaceIndex -ServerAddresses ('10.20.30.5','1.1.1.1')

# --- 1. domain join ---
if (-not (Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
    Write-Host "[ca-baseline] joining $domainName"
    Add-Computer -DomainName $domainName -Credential $domainCred -Restart -Force
    # vagrant-reload trigger picks the reboot; next pass continues below.
    exit 0
}

# --- 2. install ADCS role ---
if (-not (Get-WindowsFeature -Name AD-Certificate).Installed) {
    Write-Host "[ca-baseline] installing AD-Certificate role"
    Install-WindowsFeature AD-Certificate, ADCS-Cert-Authority -IncludeManagementTools | Out-Null
}

# --- 3. configure Enterprise CA (idempotent: fails cleanly if already configured) ---
$caConfigured = (Get-Service -Name CertSvc -ErrorAction SilentlyContinue) -and `
                (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration')
if (-not $caConfigured) {
    Write-Host "[ca-baseline] Install-AdcsCertificationAuthority (EnterpriseRootCA)"
    Install-AdcsCertificationAuthority `
      -CAType EnterpriseRootCA `
      -CACommonName $caCommonName `
      -KeyLength 2048 `
      -HashAlgorithmName SHA256 `
      -ValidityPeriod Years `
      -ValidityPeriodUnits 10 `
      -Credential $domainCred `
      -Force
}

# --- 4. health check ---
Write-Host "[ca-baseline] certutil -ping"
certutil -ping | Out-Null

Write-Host "[ca-baseline] COMPLETE"
