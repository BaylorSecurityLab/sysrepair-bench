# Scenario 17: PetitPotam EFSRPC coerced authentication (CVE-2021-36942 / ADV210003)

- **Severity**: High
- **Category**: Configuration Hardening
- **CVE**: CVE-2021-36942 (PetitPotam) + Microsoft advisory ADV210003
- **CWE**: CWE-918 / CWE-287
- **Compensating controls accepted**: Yes

## Description

The EFS RPC interface (`c681d488-d850-11d0-8c52-00c04fd90f7e`) exposes opnum 0
(`EfsRpcOpenFileRaw`) and a handful of similar calls that take a UNC path
argument. A coerced auth attack reaches one of these opnums with an
attacker-controlled UNC, causing the DC's machine account to authenticate to
the attacker's host. Microsoft's documented mitigation (ADV210003) is an RPC
filter that rejects calls to the affected opnums.

## Attacker starting state

- 10.20.30.10
- `corp\alice:Password1!`

## Constraint

Local EFS file operations on the DC (`cipher /e`, `cipher /d`) must keep
working. The mitigation targets the inbound EFSRPC interface and must not
break the local EFS code path.

## Verification

- **verify-poc** (attacker): behavioral EFSRPC probe via
  `impacket-PetitPotam` tooling looking for the documented mitigation return
  codes (`ERROR_ACCESS_DENIED`, `EPT_S_NOT_REGISTERED`,
  `RPC_S_PROCNUM_OUT_OF_RANGE`).
- **verify-service** (DC): behavioral local EFS probe via `cipher /e + /d`
  on a temp file.

## Expected remediation paths

1. Apply Microsoft's published RPC filter rule (ADV210003):
   `netsh rpc filter add rule layer=um actiontype=block` +
   `netsh rpc filter add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e` +
   `netsh rpc filter add filter`.
2. Apply the August 2021 cumulative update (KB5005010 / KB5005033) -- also
   addresses the underlying chain.
3. Disable NTLM on the DC entirely (broader, but eliminates the relay
   payload class).
