# meta4/ad-vm/provision/seed-directory.ps1
# Seeds corp.local with 3 OUs and 8 users. Idempotent.
#
# Ported from the Phase B block of the retired dc-baseline.ps1. The
# Meta4-Bootstrap scheduled-task chain that surrounded it is gone: it existed
# only because Vagrant could not survive Install-ADDSForest destroying the
# local SAM mid-session, which invalidated the WinRM session it was holding.
# AutomatedLab's RootDC role promotes the DC out of band, so promotion is not
# this script's concern and the entire self-driving bootstrap chain -- the
# scheduled task, the reboot dance, the 30-minute marker poll -- is deleted.
#
# The `vagrant -> Domain Admins` step is also dropped: there is no vagrant
# account under AutomatedLab.
#
# Invoked over PowerShell Direct (VMBus, no network path).

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory

$domainDN = 'DC=corp,DC=local'
$seedPass = ConvertTo-SecureString 'Password1!' -AsPlainText -Force

Write-Host '[seed] organisational units'
foreach ($ou in @('Corp', 'IT', 'Service')) {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou -Path $domainDN -ProtectedFromAccidentalDeletion:$false
        Write-Host "[seed] created OU=$ou"
    }
}

Write-Host '[seed] users'
$seedUsers = @(
    @{ name = 'alice';   ou = 'Corp'    },
    @{ name = 'bob';     ou = 'Corp'    },
    @{ name = 'carol';   ou = 'Corp'    },
    @{ name = 'dave';    ou = 'IT'      },
    @{ name = 'eve';     ou = 'IT'      },
    @{ name = 'svc_sql'; ou = 'Service' },
    @{ name = 'svc_web'; ou = 'Service' },
    @{ name = 'svc_bkp'; ou = 'Service' }
)
foreach ($u in $seedUsers) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.name)'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $u.name -SamAccountName $u.name `
            -AccountPassword $seedPass `
            -Path "OU=$($u.ou),$domainDN" `
            -Enabled $true -PasswordNeverExpires $true
        Write-Host "[seed] created user=$($u.name) ou=$($u.ou)"
    }
}

# Scenarios and ca-postinstall.ps1 both authenticate as CORP\Administrator with
# this password. AutomatedLab sets it at install time; reasserting it here means
# a re-seed against a hand-modified lab converges.
Set-ADAccountPassword -Identity Administrator -Reset -NewPassword $seedPass
Set-ADUser -Identity Administrator -PasswordNeverExpires $true
Write-Host '[seed] reset CORP\Administrator password'

# Continuity marker. Save-LabBaseline checks for this before capturing, and the
# old harness wrote it at the end of its bootstrap chain.
New-Item -ItemType Directory -Path 'C:\meta4-setup' -Force | Out-Null
New-Item -ItemType File -Path 'C:\meta4-setup\BOOTSTRAP_COMPLETE' -Force | Out-Null

Write-Host '[seed] COMPLETE'
