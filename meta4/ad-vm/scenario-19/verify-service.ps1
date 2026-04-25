$ErrorActionPreference = 'Stop'
try {
    $sec  = ConvertTo-SecureString 'Password1!' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator', $sec)

    $hostname = Invoke-Command -ComputerName corp-ca01 -Credential $cred -ScriptBlock {
        $env:COMPUTERNAME
    } -ErrorAction Stop

    if ($hostname -ne 'CORP-CA01') {
        throw "Unexpected hostname returned: $hostname"
    }
    Write-Host "[verify-service-19] WinRM Invoke-Command to corp-ca01 OK -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-19] $_"; exit 1
}
