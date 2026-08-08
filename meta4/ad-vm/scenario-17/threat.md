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
  `impacket-PetitPotam` against the DC as `corp\alice`. **The tool walks a
  list of EFSRPC functions**, so a denial for one of them proves nothing on
  its own -- `EfsRpcOpenFileRaw` has been patched since August 2021 and
  reports `RPC_ACCESS_DENIED` even on a fully coercible host, after which
  the tool moves on to a function that still works. The verdict is
  therefore: FAIL if any success marker appears anywhere in the transcript
  (`Attack worked`, or `ERROR_BAD_NETPATH`, which is the DC confirming it
  tried to reach the attacker's UNC path); PASS only if **every** function
  tried was refused (`ACCESS_DENIED`, `EPT_S_NOT_REGISTERED`,
  `RPC_S_PROCNUM_OUT_OF_RANGE`, RPC filtered) with no success marker at all.
  An unreachable DC is graded a harness error, never a pass.
- **verify-service** (DC): behavioral local EFS probe via `cipher /e + /d`
  on a temp file. The mitigation must block the *inbound* EFSRPC interface
  without breaking the local EFS code path.

## Expected remediation paths

1. Apply Microsoft's published RPC filter rule (ADV210003) on the DC,
   blocking the EFSRPC interface at the user-mode layer. Two points that
   decide whether this works:
   - **The rule, its condition and its commit are one transaction inside a
     single `netsh rpc filter` session.** `add rule` opens a rule,
     `add condition` attaches to the rule in progress, and `add filter`
     commits it. Three separate `netsh ...` invocations each start a fresh
     session, so the condition has no rule to attach to and nothing is
     applied. Drive it from one interactive session, or from a script fed to
     `netsh -f` whose **first line is `rpc filter`** — `netsh -f` replays
     from netsh's root context, and a script starting at `filter` leaves
     netsh at the root where that is not a command, exits non-zero and
     applies nothing.
   - **Block both EFSRPC interface UUIDs**, not just the modern one:
     `c681d488-d850-11d0-8c52-00c04fd90f7e` (MS-EFSR) and
     `df1941c5-fe89-4e79-bf10-463657acf44d` (the legacy interface the tool
     also accepts). Blocking one leaves the other coercible.

   Verify with `netsh rpc filter show filter` that the UUIDs are actually
   listed rather than trusting the exit code. The filter applies to the
   running RPC runtime immediately; no service restart is required.
2. The August 2021 cumulative update (KB5005010 / KB5005033) is the vendor
   fix in a connected environment. **This lab has no route to the internet
   and no update package is staged locally**, so it is not available here;
   do not attempt to download it. Note also that it hardens
   `EfsRpcOpenFileRaw` specifically -- the other EFSRPC functions remain
   callable, which is why Microsoft published the RPC filter alongside it.
3. Disabling NTLM on the DC addresses the *relay* that follows the coercion,
   not the coercion itself: the EFSRPC interface still accepts the call and
   the DC still reaches out to the attacker's path. Treat it as broader
   hardening, not as a fix for this finding.
