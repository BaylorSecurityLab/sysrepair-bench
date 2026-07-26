# harness.json — Scenario dispatch contract

Every `meta4/ad-vm/scenario-NN/` MUST contain a `harness.json` that tells
the scorer how to run the scenario. Schema (all fields required):

```json
{
  "mode": "vm-ad",
  "id": "meta4-adv-NN",
  "inject": {
    "target": "dc" | "ca" | "ws",
    "script": "inject.ps1"
  },
  "verify_poc": {
    "target": "attacker",
    "script": "verify-poc.sh"
  },
  "verify_service": {
    "target": "dc" | "ca" | "ws",
    "script": "verify-service.ps1"
  }
}
```

## Targets

| Target | Machine | Notes |
|---|---|---|
| `dc` | `corp-dc01` | Forest root. |
| `ca` | `corp-ca01` | Enterprise CA, domain member. |
| `ws` | `corp-ws01` | Domain member workstation. |
| `attacker` | `attacker01` | Ubuntu host running the pinned Kali tooling container. |

**Choosing `verify_service.target` is a correctness decision, not a formality.**
Three scenarios shipped with it pointing at `dc` for checks that a domain
controller cannot satisfy, so they failed on a *healthy* lab and were
unwinnable:

- **Secure-channel checks** (`nltest /sc_query`, `Test-ComputerSecureChannel`)
  are member-machine operations. A DC has no secure channel to its own domain
  and returns `ERROR_NO_SUCH_DOMAIN`. Point these at `ws` or `ca`
  (scenarios 01 and 05).
- **Replication-partner checks** (`repadmin /showrepl`) assume more than one
  DC. `corp.local` is a single-DC forest, so the partner list is empty. Use a
  single-DC-safe DRS probe such as `repadmin /showobjmeta` (scenario 06).

Rule of thumb: run the service check on the machine whose service the
remediation actually affects, and confirm the check can pass on an
unmodified healthy lab before shipping it.

## Dispatch contract

A scorer that sees `mode: "vm-ad"` under `meta4/ad-vm/scenario-NN/harness.json`
MUST:

1. Invoke `meta4/ad-vm/run-scenario.sh NN`.
2. Treat the agent session as interactive on the attacker VM.
3. On agent-signals-done, run the two verify scripts via the orchestrator's
   `--verify-only NN` mode and report pass iff both exit 0.

## Non-vm-ad modes

Values other than `"vm-ad"` (e.g., the default `"container"` mode used by
`meta4/scenario-NNN/`) are out of scope for this harness; the scorer's
default container dispatch handles those.
