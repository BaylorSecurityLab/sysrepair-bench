# meta4/ad-vm/scenario-19/reference-fix.ps1
# Reference remediation for LAPS not enforced on corp-ws01.
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# The exposure is a member server whose local Administrator password is a
# known shared default. LAPS exists to make that password unique per machine
# and rotated; with it unmanaged, one leaked credential unlocks every host
# that shares it.
#
# verify-poc.sh probes whether the DEFAULT credential still authenticates over
# RDP NLA. So the remediation that matters -- and the one an agent would
# actually perform -- is to rotate the local Administrator password to a
# unique value and mark the account as managed.
#
# This fixture rotates to a strong random password rather than a hardcoded
# one, so re-running it does not leave a second known-shared credential
# behind, which would be the same defect in a new costume.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

# Strong random password: 24 chars from a set that satisfies complexity.
$chars = ([char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ') + ([char[]]'abcdefghijkmnpqrstuvwxyz') +
         ([char[]]'23456789') + ([char[]]'!@#$%^&*-_=+')
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 24
$rng.GetBytes($bytes)
$newPwd = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })

$sec  = ConvertTo-SecureString 'Password1!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator', $sec)

Invoke-Command -ComputerName corp-ws01 -Credential $cred -ArgumentList $newPwd -ScriptBlock {
    param($pwd)
    # Rotate the local Administrator password away from the shared default.
    & net user Administrator $pwd | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "net user returned $LASTEXITCODE" }
}

# THE LAPS SCHEMA IS NOT EXTENDED IN THIS LAB, so there is no
# ms-Mcs-AdmPwdExpirationTime attribute to set. Confirmed against the live
# directory: ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime and msLAPS-Password are
# all absent from the schema.
#
# The previous code here wrote that attribute with -ErrorAction
# SilentlyContinue, which did NOT suppress the failure: an invalid property is
# a terminating .NET ArgumentException, not a non-terminating cmdlet error, so
# SilentlyContinue never applied and this fixture threw after rotating the
# password. inject.ps1 had the identical bug and threw BEFORE doing its work.
#
# Removed rather than papered over. What this scenario actually measures is
# behavioural -- whether the default credential still authenticates over RDP --
# and rotating the password to a unique value is the real remediation. Setting
# a directory attribute that no schema defines would add nothing an agent could
# do, and nothing verify-poc.sh could observe.
#
# If the lab ever extends the LAPS schema, the managed-flag handling belongs
# back here AND in inject.ps1, in agreement.

Write-Host '[fix-19] corp-ws01 local Administrator password rotated to a unique random value'
Write-Host '[fix-19] (LAPS schema not extended in this lab; rotation is the observable control)'
Write-Host '[fix-19] COMPLETE'
