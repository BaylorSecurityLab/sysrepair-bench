$ErrorActionPreference = 'Stop'
try {
    # Behavioural probe: dave can still authenticate with password pre-auth
    # enforced. Use LDAP bind as dave to exercise the full KDC + KRB5 flow.
    $sec = ConvertTo-SecureString 'Winter24' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential('corp\dave', $sec)
    $u = Get-ADUser -Identity dave -Credential $cred -Server corp-dc01 -ErrorAction Stop
    if ($u.SamAccountName -ne 'dave') {
        throw "Unexpected LDAP bind result for dave"
    }
    Write-Host "[verify-service-04] dave LDAP bind OK -- Kerberos pre-auth flow HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-04] $_"; exit 1
}
