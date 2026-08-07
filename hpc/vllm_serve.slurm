#!/bin/bash
# Serve a vLLM OpenAI-compatible endpoint on 4x NVIDIA H200 (half of one Delta
# gpuH200x8 node), protected by a per-job API key.
#
#   sbatch --account=<your-project> hpc/vllm_serve.slurm
#
# Override the model without editing this file:
#   VLLM_MODEL=Qwen/Qwen2.5-7B-Instruct sbatch --account=<acct> --export=ALL hpc/vllm_serve.slurm
#
# On startup this writes ~/.vllm_delta/conn_<jobid>.env containing the node,
# port and API key. hpc/tunnel.ps1 reads that file to build the SSH tunnel.
#
# NOTE: --account is intentionally NOT hardcoded. Run `accounts` on a login
# node and pass the "Project" value on the sbatch command line.
#
# PARALLELISM WARNING (Qwen3.5-397B-A17B-FP8):
#   `-tp 4` is a known-broken configuration for this model — vLLM issue #34893
#   reports fused linear layer sharding failure on exactly 4x H200, and
#   --enable-expert-parallel did not rescue it. Default here is therefore
#   data-parallel attention + expert-parallel MoE (`-dp 4 --enable-expert-parallel`),
#   which shards the 512 experts without hitting the fused-linear TP path.
#   Set VLLM_PARALLEL_MODE=tp only for models known to shard cleanly.

#SBATCH --job-name=vllm-serve
#SBATCH --partition=gpuH200x8
#SBATCH --nodes=1
#SBATCH --gpus-per-node=4
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=48
#SBATCH --mem=1000g
#SBATCH --time=00:30:00
#SBATCH --constraint="scratch"
#SBATCH --no-requeue
#SBATCH --output=slurm-%j.out
#SBATCH --error=slurm-%j.err

set -euo pipefail

module reset

# ---------------------------------------------------------------- configuration
# A 397B checkpoint will NOT finish loading inside a 30-minute allocation on a
# cold cache. Validate the whole path (tunnel + API key + Inspect) with a small
# model first, then raise --time only once the plumbing is proven.
MODEL="${VLLM_MODEL:-Qwen/Qwen2.5-7B-Instruct}"
SERVED_NAME="${VLLM_SERVED_NAME:-$(basename "$MODEL")}"
MAX_LEN="${VLLM_MAX_LEN:-32768}"
GPU_UTIL="${VLLM_GPU_UTIL:-0.92}"
N_GPUS="${VLLM_N_GPUS:-4}"
PARALLEL_MODE="${VLLM_PARALLEL_MODE:-dp-ep}"   # dp-ep | tp
# Extra flags appended verbatim; use for --reasoning-parser, --language-model-only, etc.
EXTRA_ARGS="${VLLM_EXTRA_ARGS:-}"

# HOME (/u) is capped at 100 GB — a 397B checkpoint is ~400 GB and will blow the
# quota and fail mid-download. Keep the HF cache on the work filesystem.
export HF_HOME="${SCRATCH:-/work/hdd/$USER}/hf"
export HF_HUB_ENABLE_HF_TRANSFER=1
export VLLM_WORKER_MULTIPROC_METHOD=spawn
export OMP_NUM_THREADS=8
mkdir -p "$HF_HOME"

# ------------------------------------------------------------------- networking
# Derive a per-job high port so concurrent jobs never collide.
PORT=$(( 20000 + (SLURM_JOB_ID % 20000) ))
NODE="$(hostname -s)"
API_KEY="$(openssl rand -hex 24)"

CONN_DIR="$HOME/.vllm_delta"
CONN_FILE="$CONN_DIR/conn_${SLURM_JOB_ID}.env"
mkdir -p "$CONN_DIR"
chmod 700 "$CONN_DIR"

# Written before the server is up so the tunnel can be started while it loads;
# 0600 because it carries the bearer token.
umask 077
cat > "$CONN_FILE" <<EOF
VLLM_JOB_ID=${SLURM_JOB_ID}
VLLM_NODE=${NODE}
VLLM_PORT=${PORT}
VLLM_API_KEY=${API_KEY}
VLLM_SERVED_NAME=${SERVED_NAME}
VLLM_MODEL=${MODEL}
EOF
chmod 600 "$CONN_FILE"

echo "=============================================================="
echo " job        : ${SLURM_JOB_ID}"
echo " node       : ${NODE}"
echo " port       : ${PORT}"
echo " model      : ${MODEL}  (served as '${SERVED_NAME}')"
echo " gpus       : ${N_GPUS} x H200   mode: ${PARALLEL_MODE}"
echo " conn file  : ${CONN_FILE}"
echo "=============================================================="
nvidia-smi --query-gpu=index,name,memory.total --format=csv,noheader || true

# ------------------------------------------------------------------ launch vLLM
# --host 0.0.0.0 is required: the tunnel terminates on the login node, which
# must reach this process over the cluster's internal network. Binding to
# loopback would make it unreachable. Compute nodes are not publicly routable,
# and --api-key is the access control layered on top of that.
VLLM_ARGS=(
  --model "$MODEL"
  --served-model-name "$SERVED_NAME"
  --host 0.0.0.0
  --port "$PORT"
  --api-key "$API_KEY"
  --gpu-memory-utilization "$GPU_UTIL"
  --max-model-len "$MAX_LEN"
  --enable-prefix-caching
  --trust-remote-code
  --disable-log-requests
)

case "$PARALLEL_MODE" in
  dp-ep) VLLM_ARGS+=(-dp "$N_GPUS" --enable-expert-parallel) ;;
  tp)    VLLM_ARGS+=(-tp "$N_GPUS") ;;
  *)     echo "ERROR: VLLM_PARALLEL_MODE must be dp-ep or tp" >&2; exit 1 ;;
esac

# shellcheck disable=SC2206
[[ -n "$EXTRA_ARGS" ]] && VLLM_ARGS+=($EXTRA_ARGS)

# Pick whichever launcher exists on Delta. `module avail vllm` and
# `module help llmflux` will tell you what is actually installed; adjust here.
if command -v vllm >/dev/null 2>&1; then
  echo "[launch] using vllm from PATH"
  vllm serve "${VLLM_ARGS[@]}" &
elif [[ -n "${VLLM_SIF:-}" && -f "$VLLM_SIF" ]]; then
  echo "[launch] using apptainer image $VLLM_SIF"
  apptainer exec --nv \
    --bind "$HF_HOME:$HF_HOME" \
    --env "HF_HOME=$HF_HOME" \
    "$VLLM_SIF" vllm serve "${VLLM_ARGS[@]}" &
else
  echo "ERROR: no vllm on PATH and VLLM_SIF unset." >&2
  echo "       module load the site vLLM, activate a venv, or export VLLM_SIF=/path/to/vllm.sif" >&2
  exit 1
fi
VLLM_PID=$!

# Tear the server down cleanly if Slurm signals the job.
trap 'echo "[trap] stopping vllm"; kill "$VLLM_PID" 2>/dev/null || true' TERM INT EXIT

# --------------------------------------------------------------- readiness wait
echo "[wait] polling http://${NODE}:${PORT}/health"
for _ in $(seq 1 300); do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    echo "=============================================================="
    echo " READY. From your laptop (PowerShell):"
    echo "   ssh -N -L 127.0.0.1:8001:${NODE}:${PORT} ${USER}@dt-login01.delta.ncsa.illinois.edu"
    echo " Then point Inspect at http://localhost:8001/v1"
    echo " API key is in ${CONN_FILE}"
    echo "=============================================================="
    break
  fi
  # Bail out early if vLLM died during load rather than polling to the wall.
  kill -0 "$VLLM_PID" 2>/dev/null || { echo "ERROR: vllm exited during startup" >&2; exit 1; }
  sleep 5
done

wait "$VLLM_PID"
