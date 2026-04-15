# SysRepair-Bench — Inspect AI harness

Runs the SysRepair-Bench scenarios (`meta2/`, `vulnhub/`, `ccdc/`) under
[Inspect AI](https://inspect.aisi.org.uk/) with one of five solver strategies.

## Setup (uv)

```bash
cd inspect_eval
uv sync
```

Docker must be installed and running (each scenario builds its own image from
its `Dockerfile`).

## Running

Examples (run from `inspect_eval/`):

```bash
# All scenarios across all benchmarks, ReAct (built-in)
uv run inspect eval sysrepair_bench --model openai/gpt-4o-mini

# Only meta2, with the LATS solver
uv run inspect eval sysrepair_bench --model openai/gpt-4o \
    -T solver=lats -T benchmarks='["meta2"]'

# A specific scenario list
uv run inspect eval sysrepair_bench --model openai/gpt-4o \
    -T solver=reflexion \
    -T scenarios='["meta2/scenario-01","vulnhub/scenario-03"]'

# Local Ollama via OpenAI-compatible endpoint
OPENAI_BASE_URL=http://10.100.203.130:11434/v1 OPENAI_API_KEY=ollama \
    uv run inspect eval sysrepair_bench --model openai/devstral-2:123b \
    -T solver=plan_and_solve
```

## Task parameters (`-T key=value`)

| Param           | Default                              | Meaning                                                                 |
|-----------------|--------------------------------------|-------------------------------------------------------------------------|
| `solver`        | `react`                              | One of `react`, `basic`, `reflexion`, `plan_and_solve`, `lats`.         |
| `benchmarks`    | `["meta2","vulnhub","ccdc"]`         | Filter by benchmark directory.                                          |
| `scenarios`     | unset                                | Explicit list (e.g. `["meta2/scenario-01"]`); overrides `benchmarks`.   |
| `message_limit` | `40`                                 | Per-sample message budget (forced-halt cap).                            |
| `max_attempts`  | `1`                                  | ReAct resubmission attempts on scorer feedback.                         |

## Scoring

Each sample is scored by copying its `verify.sh` into the running sandbox and
checking the exit code (`0 = CORRECT`). The agent declares completion via the
`submit()` tool (provided automatically by `react()` and the other solvers
that wrap it). Hitting `message_limit` without submitting counts as a forced
halt and is scored against the unmodified container state.

## Solver notes

- **react** — `inspect_ai.agent.react()` with a `bash` tool; uses Inspect's
  built-in `submit()` semantics.
- **basic** — Minimal generate+tool loop; ends when the model stops calling
  tools or hits the message limit.
- **reflexion** — Up to 3 ReAct cycles. Between cycles a reflector LLM call
  produces a correction strategy that is appended to the system prompt.
- **plan_and_solve** — One JSON plan call up front, then sequential execution
  with per-step retry. Stops as soon as `verify.sh` passes.
- **lats** — UCB1-driven MCTS; an LLM both expands candidate commands and
  scores rollouts. Container state accumulates across rollouts (Strategy C).
