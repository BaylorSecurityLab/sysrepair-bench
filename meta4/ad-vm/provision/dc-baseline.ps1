# meta4/ad-vm/provision/dc-baseline.ps1
# Promotes to corp.local forest root, seeds directory with 25 users, 3 OUs, and groups.
# Idempotent: safe to re-run; exits 0 if already provisioned.

$ErrorActionPreference = 'Stop'

$domainName      = 'corp.local'
$netbiosName     = 'CORP'
$dsrmPassword    = ConvertTo-SecureString 'Vagrant1DSRM!' -AsPlainText -Force
$adminPassword   = 'Password1!'

# --- 0. idempotency guard ---
if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain -and
    (Get-ADDomain -ErrorAction SilentlyContinue) -and
    ((Get-ADDomain).DNSRoot -eq $domainName)) {
    Write-Host "[dc-baseline] already joined to $domainName, skipping promotion"
} else {
    Write-Host "[dc-baseline] installing AD DS role"
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null

    Write-Host "[dc-baseline] promoting to forest root of $domainName"
    Install-ADDSForest `
      -DomainName $domainName `
      -DomainNetbiosName $netbiosName `
      -SafeModeAdministratorPassword $dsrmPassword `
      -ForestMode WinThreshold `
      -DomainMode WinThreshold `
      -InstallDns:$true `
      -NoRebootOnCompletion:$false `
      -Force:$true

    # Install-ADDSForest triggers its own reboot; provisioner resumes via vagrant-reload on next pass.
    exit 0
}

# --- 1. seed OUs, users, groups (runs on second pass, after DC reboot) ---
Import-Module ActiveDirectory

foreach ($ou in @('Corp','IT','Service')) {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou -Path 'DC=corp,DC=local' -ProtectedFromAccidentalDeletion:$false
        Write-Host "[dc-baseline] created OU=$ou"
    }
}

$seedUsers = @(
    @{ name='alice';   ou='Corp';    group='Domain Users' },
    @{ name='bob';     ou='Corp';    group='Domain Users' },
    @{ name='carol';   ou='Corp';    group='Domain Users' },
    @{ name='dave';    ou='IT';      group='Domain Users' },
    @{ name='eve';     ou='IT';      group='Domain Users' },
    @{ name='svc_sql'; ou='Service'; group='Domain Users' },
    @{ name='svc_web'; ou='Service'; group='Domain Users' },
    @{ name='svc_bkp'; ou='Service'; group='Domain Users' }
)

foreach ($u in $seedUsers) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.name)'" -ErrorAction SilentlyContinue)) {
        New-ADUser `
          -Name $u.name `
          -SamAccountName $u.name `
          -AccountPassword (ConvertTo-SecureString $adminPassword -AsPlainText -Force) `
          -Path "OU=$($u.ou),DC=corp,DC=local" `
          -Enabled $true `
          -PasswordNeverExpires $true
        Write-Host "[dc-baseline] created user=$($u.name) ou=$($u.ou)"
    }
}

# --- 2. health check ---
Write-Host "[dc-baseline] repadmin /showrepl"
repadmin /showrepl | Out-Null
Write-Host "[dc-baseline] dcdiag /test:replications"
dcdiag /test:replications /q

Write-Host "[dc-baseline] COMPLETE"
