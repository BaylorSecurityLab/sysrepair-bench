#!/bin/bash
# Poll the state of a vLLM serve job. Safe to run on a login node -- it only
# calls squeue and one curl against the compute node.
#
#   ./hpc/status.sh              # newest vllm-serve job
#   ./hpc/status.sh 2301062      # a specific job
#
# Exit codes are meaningful so this can drive a watch loop:
#   0 = serving and healthy    2 = queued/starting
#   3 = running but unhealthy  4 = job is gone
#
# Job exit status alone is NOT a reliable signal here: vLLM can wedge during
# weight loading or after an OOM and keep the allocation alive with a dead
# server, so the health probe is what actually decides.

set -uo pipefail

JOB_ID="${1:-}"
if [[ -z "$JOB_ID" ]]; then
  JOB_ID=$(squeue -u "$USER" -n vllm-serve -h -o "%i" --sort=-i | head -1)
fi

if [[ -z "$JOB_ID" ]]; then
  echo "state=GONE  no vllm-serve job in the queue"
  exit 4
fi

read -r STATE NODE ELAPSED TIMELEFT < <(
  squeue -j "$JOB_ID" -h -o "%T %N %M %L" 2>/dev/null
) || true

if [[ -z "${STATE:-}" ]]; then
  echo "state=GONE  job $JOB_ID no longer in queue"
  echo "  last lines of slurm-${JOB_ID}.out:"
  tail -n 15 "slurm-${JOB_ID}.out" 2>/dev/null | sed 's/^/    /'
  exit 4
fi

CONN="$HOME/.vllm_delta/conn_${JOB_ID}.env"

if [[ "$STATE" != "RUNNING" ]]; then
  echo "state=$STATE  job=$JOB_ID  elapsed=$ELAPSED"
  exit 2
fi

if [[ ! -f "$CONN" ]]; then
  echo "state=RUNNING  job=$JOB_ID  node=$NODE  (no conn file yet -- still starting)"
  exit 2
fi

# shellcheck disable=SC1090
source "$CONN"

if curl -fsS --max-time 10 "http://${VLLM_NODE}:${VLLM_PORT}/health" >/dev/null 2>&1; then
  echo "state=SERVING  job=$JOB_ID  node=$VLLM_NODE  port=$VLLM_PORT  timeleft=$TIMELEFT"
  echo "  tunnel: ssh -N -L 127.0.0.1:8001:${VLLM_NODE}:${VLLM_PORT} ${USER}@dt-login01.delta.ncsa.illinois.edu"
  exit 0
fi

echo "state=LOADING  job=$JOB_ID  node=$VLLM_NODE  elapsed=$ELAPSED  timeleft=$TIMELEFT"
echo "  health probe not answering yet; recent log:"
tail -n 8 "slurm-${JOB_ID}.out" 2>/dev/null | sed 's/^/    /'
exit 3
