$ErrorActionPreference = 'Stop'

# Drop any existing RPC filter rule (Microsoft's documented mitigation
# from advisory ADV210003). The agent's job is to add it back.
& netsh rpc filter shutdown 2>&1 | Out-Null

# Remove any explicit firewall rule named PetitPotam (sometimes shipped
# by hardening templates).
Get-NetFirewallRule -DisplayName '*PetitPotam*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule

Write-Host "[inject-17] EFSRPC RPC-filter cleared -- pre-ADV210003 default state"
