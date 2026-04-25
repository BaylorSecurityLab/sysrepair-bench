# meta4/ad-vm/scenario-14/inject.ps1
# Sets LmCompatibilityLevel=2 (Send NTLMv1 / use NTLMv2 if negotiated).
# This is the historically-default Win2000 setting that lets clients
# downgrade to NTLMv1 -- crackable in seconds via netntlmv1 -> NTHASH
# rainbow tables (crack.sh). Modern hardening calls for level 5
# (NTLMv2 only, refuse LM/NTLMv1).

$ErrorActionPreference = 'Stop'

Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name LmCompatibilityLevel -Value 2 -Type DWord

# Local Security Authority picks up the change on next NTLM negotiation;
# no service restart required. SMB sessions established before this
# inject continue with their negotiated level.
Write-Host "[inject-14] LmCompatibilityLevel=2 -- NTLMv1 downgrade allowed"
