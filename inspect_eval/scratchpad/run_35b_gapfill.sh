#!/usr/bin/env bash
# Fills the two sr-modern gaps in the 35B day1 cell: meta4/scenario-50 (never
# ran) and meta4/scenario-43 (epoch 1 only). Five episodes.
#
# max_connections 2 on purpose: the zero_day leg is using the same vLLM
# endpoint, and this is five episodes against its several hundred, so it should
# take a thin slice rather than contend.
cd /home/resbears/projects/sysrepair-bench/inspect_eval
set -a; . ./.env >/dev/null 2>&1; set +a
echo "[gapfill] start $(date -u +%FT%TZ)"
SR_EVAL_SET=1 .venv/bin/python3 -m sysrepair_bench.run qwen35b_gapfill \
  --runs panelB/qwen35b_gapfill.runs.yaml >> scratchpad/qwen35b_gapfill.log 2>&1
echo "[gapfill] exited rc=$? $(date -u +%FT%TZ)"
