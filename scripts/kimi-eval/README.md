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
