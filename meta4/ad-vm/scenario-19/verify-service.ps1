$ErrorActionPreference = 'Stop'
try {
    $sec  = ConvertTo-SecureString 'Password1!' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator', $sec)

    $hostname = Invoke-Command -ComputerName corp-ws01 -Credential $cred -ScriptBlock {
        $env:COMPUTERNAME
    } -ErrorAction Stop

    # Uppercase because $env:COMPUTERNAME is uppercase; -ne is case-insensitive
    # anyway, but the literal should match what the machine actually reports.
    # This still said CORP-CA01 after the retarget: the bulk rename only caught
    # the lowercase spelling, so the check connected to corp-ws01 and then
    # demanded it identify itself as the CA.
    if ($hostname -ne 'CORP-WS01') {
        throw "Unexpected hostname returned: $hostname"
    }
    Write-Host "[verify-service-19] WinRM Invoke-Command to corp-ws01 OK -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-19] $_"; exit 1
}
