# meta4/ad-vm/scenario-14/reference-fix.ps1
# Reference remediation for NTLMv1 being permitted.
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# LmCompatibilityLevel:
#   2 = send NTLM, accept LM/NTLM/NTLMv2   <- the vulnerable state
#   5 = send NTLMv2 only, REFUSE LM and NTLM (NTLMv1)  <- the fix
#
# NTLMv1 responses are trivially crackable to the NT hash, so accepting them
# undermines every downstream authentication. Level 5 is the documented
# hardening for domain controllers.
#
# LSA reads this at authentication time rather than caching it at service
# start, so no restart is required and there is no gate-4 fixture for this
# scenario.

$ErrorActionPreference = 'Stop'

Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name LmCompatibilityLevel -Value 5 -Type DWord

$v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').LmCompatibilityLevel
if ($v -ne 5) { throw "[fix-14] LmCompatibilityLevel is $v, expected 5" }

Write-Host '[fix-14] LmCompatibilityLevel=5 -- NTLMv2 only, NTLMv1 refused'
Write-Host '[fix-14] COMPLETE'
