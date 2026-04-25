$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

# Clear the LAPS schema "managed" flag on corp-ca01 so subsequent LAPS
# checks see the host as unmanaged (the documented pre-LAPS state).
$ca = Get-ADComputer corp-ca01 -Properties 'ms-Mcs-AdmPwdExpirationTime' -ErrorAction SilentlyContinue
if ($ca -and $ca.'ms-Mcs-AdmPwdExpirationTime') {
    Set-ADComputer corp-ca01 -Clear 'ms-Mcs-AdmPwdExpirationTime'
}

# Reset CA's local Administrator pwd to the well-known default. We
# coordinate via PSRemoting using the bootstrap-Phase-B Administrator pwd.
$sec  = ConvertTo-SecureString 'Password1!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator', $sec)
Invoke-Command -ComputerName corp-ca01 -Credential $cred -ScriptBlock {
    net user Administrator 'Vagrant1DSRM!'
}

Write-Host "[inject-19] LAPS managed flag cleared + corp-ca01 local Administrator pwd at known default"
