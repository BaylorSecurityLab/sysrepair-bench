# Kimi-K3 CLI eval harness

Drives Kimi-K3 through the Moonshot coding CLI (`kimi -m kimi-code/k3`, headless
`-p` print mode) against SysRepair-Bench scenarios, inside a locked runner
container whose only tool is the `srx` bash-exec bridge into the target scenario
container (matching every other agent's affordances).

- `bin/kimi_run_all.sh [concurrency]` — loops scenarios x epochs, resumable via
  `results/results.csv`. Currently meta2-hardcoded (scenario-01..40, Ubuntu-8.04
  prompt); generalize the scenario glob + prompt to reuse for other suites.
- `bin/kimi_episode.sh NN EPOCH` — one independent episode.
- `bin/srx-runner` — the single bash-exec tool exposed to the agent.
- `harness-agent.md` — the agent instructions (`--agent-file`).
- `runner-img/Dockerfile` — the `kimi-runner` container image.

AUTH: needs an interactive `kimi` login on the host first (populates
`~/.kimi-code/{config.toml,device_id,credentials/,oauth}`); the runner docker-cp's
a throwaway copy into each container. Credentials are never committed.

## The `kimi` binary (required, not committed)

`runner-img/Dockerfile` does `COPY bin/kimi /usr/local/bin/kimi`, but the vendor
CLI binary is intentionally NOT in this repo (it is a third-party binary and would
bloat the tree). Before building the runner image you must drop a **Linux** `kimi`
binary at `scripts/kimi-eval/bin/kimi` (the runner is `FROM ubuntu:22.04`, so a
Windows install will not work). Obtain it from the Moonshot/kimi-code distribution
for Linux. Without it, `docker build` fails at the COPY with no other hint.

## Architectural constraint (Docker mode)

The runner is a Linux container and `srx` reaches the target via HTTP to an
exec-agent on port 9000 inside the TARGET scenario container. This works only when
runner and target are both Linux containers (meta2, vulnhub, ccdc, meta3/ubuntu,
meta4, ad-vm). It CANNOT drive the `meta3/windows` track (Windows containers):
runner and target would need opposite Docker Desktop modes simultaneously, which one
engine cannot do. Windows-container scenarios need a second engine/host or a
host-native runner rework.
