# SysRepair-Bench — Inspect AI harness

Runs the SysRepair-Bench scenarios (`ccdc/`, `meta2/`, `meta3/ubuntu/`,
`vulnhub/`, `meta4/`, `hivestorm/`) under
[Inspect AI](https://inspect.aisi.org.uk/) with one of five solver strategies
and two evaluation modes.

## Setup (uv)

```bash
cd inspect_eval
uv sync
```

Docker must be installed and running (each scenario builds its own image from
its `Dockerfile`).

### Pre-build steps

**meta2 (Ubuntu 8.04 Hardy)** — requires a shared base image with a GNU
`timeout` shim (Hardy's coreutils 6.10 predates the binary). The harness
builds it automatically on first run, or manually:

```bash
docker build -t sysrepair/meta2-hardy:latest meta2/_base
```

**hivestorm** — requires randomized `roles.json` + `task.md` generated before
each run (anti-memorization):

```bash
SEED=42 bash hivestorm/prepare.sh
```

## Running

### Named presets (recommended)

Presets are defined in `runs.yaml`. Run from `inspect_eval/`:

```bash
# Day-1 mode: agent receives full threat briefing
uv run python -m sysrepair_bench.run all_solvers_gemma4_31b_day1

# Zero-day mode: agent must discover + remediate blind
uv run python -m sysrepair_bench.run all_solvers_gemma4_31b_zero_day

# Hivestorm free-roam (partial credit, 9 Linux scenarios)
uv run python -m sysrepair_bench.run hivestorm_linux_gemma4_31b

# Meta4 smoke test (5 representative scenarios)
uv run python -m sysrepair_bench.run meta4_smoke
```

### Direct Inspect CLI

```bash
# All scenarios across default benchmarks, ReAct
uv run inspect eval sysrepair_bench --model openai/gpt-4o-mini

# Only meta2, with the LATS solver
uv run inspect eval sysrepair_bench --model openai/gpt-4o \
    -T solver=lats -T benchmarks='["meta2"]'

# A specific scenario list
uv run inspect eval sysrepair_bench --model openai/gpt-4o \
    -T solver=reflexion \
    -T scenarios='["meta2/scenario-01","vulnhub/scenario-03"]'

# Local vLLM via OpenAI-compatible endpoint
OPENAI_BASE_URL=http://localhost:8001/v1 OPENAI_API_KEY=vllm \
    uv run inspect eval sysrepair_bench --model openai/gemma-4-31b
```

## Evaluation modes

| Mode | Prompt | Measures |
|------|--------|----------|
| `day1` (default) | Full `threat.md` briefing (CVE, affected config, expected remediation) | Execution capability: can the agent apply a known fix? |
| `zero_day` | No briefing — agent must discover + remediate blind | Discovery + execution: enumerate, identify, remediate. |

Set via `-T mode=day1` or `-T mode=zero_day`, or in a preset's `mode:` field.

## Task parameters (`-T key=value`)

| Param           | Default                              | Meaning                                                                 |
|-----------------|--------------------------------------|-------------------------------------------------------------------------|
| `solver`        | `react`                              | One of `react`, `basic`, `reflexion`, `plan_and_solve`, `lats`.         |
| `mode`          | `day1`                               | `day1` (with briefing) or `zero_day` (blind discovery).                 |
| `benchmarks`    | `["meta2","vulnhub","ccdc"]`         | Filter by benchmark directory.                                          |
| `scenarios`     | unset                                | Explicit list (e.g. `["meta2/scenario-01"]`); overrides `benchmarks`.   |
| `message_limit` | `40`                                 | Per-sample message budget (forced-halt cap).                            |
| `max_attempts`  | `1`                                  | ReAct resubmission attempts on scorer feedback.                         |
| `time_limit`    | `1800`                               | Per-sample wall-clock ceiling (seconds).                                |
| `token_limit`   | `500000`                             | Per-sample token ceiling (input + output).                              |
| `bash_timeout`  | `180`                                | Per-command timeout for the shell tool (seconds).                       |
| `verify_timeout`| `300`                                | Timeout for verify.sh execution in the scorer (seconds).                |

## Tools

The agent receives these tools (varies by benchmark):

| Tool | Provided to | Description |
|------|-------------|-------------|
| `shell` | All scenarios | OS-aware command execution (bash on Linux, PowerShell on Windows) |
| `text_editor` | ccdc, vulnhub, meta3, meta4 | View, create, str_replace, insert, undo_edit on files |
| `text_editor` (Hardy) | meta2 | Lightweight pure-shell implementation (Inspect's native editor fails on Ubuntu 8.04) |
| `think` | All scenarios | Reasoning scratchpad (no side effects) |
| `score_progress` | hivestorm only | Runs verify.sh mid-loop; returns passing checks + earned points |
| `submit` | All scenarios | Declare remediation finished (built into ReAct solver) |

## Scoring

| Benchmark | Scorer | Method |
|-----------|--------|--------|
| ccdc, meta2, meta3, meta4, vulnhub | `dispatch_scorer` (binary) | Copies `verify.sh` into sandbox, runs it. Exit 0 = CORRECT. |
| hivestorm | `dispatch_scorer` (weighted) | Parses JSONL output from verify.sh. Sums passed check weights, subtracts 10 per broken service, divides by total. Score = 0.0-1.0. |

## Solver notes

- **react** — `inspect_ai.agent.react()` with shell + text_editor + think
  tools; uses Inspect's built-in `submit()` semantics.
- **basic** — Minimal generate+tool loop; ends when the model stops calling
  tools or hits the message limit.
- **reflexion** — Up to 3 ReAct cycles. Between cycles a reflector LLM call
  produces a correction strategy appended to the system prompt.
- **plan_and_solve** — One JSON plan call up front, then sequential execution
  with per-step retry. Stops as soon as `verify.sh` passes.
- **lats** — UCB1-driven MCTS; an LLM both expands candidate commands and
  scores rollouts. Container state accumulates across rollouts.

## Container compatibility notes

| Base image | Timeout | text_editor | Notes |
|------------|---------|-------------|-------|
| Ubuntu 25.10 (ccdc) | Native GNU | Inspect native | Full support |
| Ubuntu 14.04 (meta3) | Native GNU | Inspect native | mirrors.kernel.org for apt |
| Ubuntu 8.04 Hardy (meta2) | Exec-based shim | Hardy-compatible | `sysrepair/meta2-hardy:latest` base image |
| Debian 11 (vulnhub) | Native GNU | Inspect native | Full support |
| Metasploitable2 (vulnhub/05) | Exec-based shim | Inspect native | Shim baked into Dockerfile |
| CentOS 7 (hivestorm/12) | Native GNU | Inspect native | EPEL for jq; vault.centos.org repos |
| Alpine/docker:dind (hivestorm/15) | Native | Inspect native | Needs `apk upgrade` before install |
