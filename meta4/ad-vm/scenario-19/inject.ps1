# meta4/ad-vm/scenario-19/inject.ps1
#
# RETARGETED from corp-ca01 to corp-ws01.
#
# This scenario was written before the lab had a Windows client, so it used the
# CA as a stand-in member server. Two reasons to move it:
#
#  1. LAPS exists to manage local Administrator passwords on member
#     workstations. Testing it on the machine that is also the enterprise CA
#     misrepresents the control.
#  2. It put the CA's local Administrator into a KNOWN DEFAULT state, on the
#     same host scenarios 07-11 depend on for enrollment. A scenario should not
#     weaken a machine other scenarios rely on.
#
# corp-ws01 is 10.20.30.20; corp-ca01 is 10.20.30.6. The PoC's target address
# changes with this file -- they must stay in agreement.

# THE LAPS ATTRIBUTE CODE THAT USED TO BE HERE NEVER RAN, AND HID THE REST.
#
# It called
#   Get-ADComputer <host> -Properties 'ms-Mcs-AdmPwdExpirationTime' -ErrorAction SilentlyContinue
# on a directory whose LAPS schema is not extended. Verified live: ms-Mcs-AdmPwd,
# ms-Mcs-AdmPwdExpirationTime and msLAPS-Password are all absent.
#
# Requesting an undefined property raises a TERMINATING ArgumentException
# ("One or more properties are invalid"), which -ErrorAction SilentlyContinue
# does not suppress -- that only applies to non-terminating errors. So this
# script threw on its first statement and the password reset below, the part
# verify-poc.sh actually measures, never executed.
#
# It went unnoticed because the PoC still reported the host exploitable: the
# local Administrator password was already at the build-time default, so gate 1
# passed on state the inject had not created. An inject that does nothing looks
# exactly like an inject that works, whenever the baseline already matches.
#
# The scenario's substance is behavioural and is preserved: a member client
# whose local Administrator password is a known shared default, which is the
# exposure LAPS addresses. reference-fix.ps1 rotates it to a unique value.

$ErrorActionPreference = 'Stop'

# Reset the client's local Administrator pwd to the well-known default. We
# coordinate via PSRemoting using the bootstrap-Phase-B Administrator pwd.
$sec  = ConvertTo-SecureString 'Password1!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator', $sec)
Invoke-Command -ComputerName corp-ws01 -Credential $cred -ScriptBlock {
    net user Administrator 'Vagrant1DSRM!'
}

Write-Host "[inject-19] corp-ws01 local Administrator pwd set to the known shared default"
