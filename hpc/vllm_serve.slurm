#!/bin/bash
# Serve Qwen3.5-397B-A17B-FP8 on Delta H200s behind a per-job API key.
#
#   sbatch --account=beri-delta-gpu --gpus-per-node=4 hpc/vllm_serve.slurm
#   sbatch --account=beri-delta-gpu --gpus-per-node=8 --exclusive hpc/vllm_serve.slurm
#
# IMPORTANT: Slurm snapshots this script at submit time, and the gpuH200x8 queue
# is currently ~5 days deep. So all vLLM tuning lives in an EXTERNAL file read
# at job start:
#
#     ~/hpc/vllm_args.env
#
# Edit that file any time before the job runs to change flags without
# resubmitting and losing queue position.

#SBATCH --job-name=vllm-qwen35
#SBATCH --partition=gpuH200x8
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=48
#SBATCH --mem=1000g
#SBATCH --time=02:00:00
#SBATCH --constraint="scratch"
#SBATCH --no-requeue
#SBATCH --output=slurm-vllm-%j.out
#SBATCH --error=slurm-vllm-%j.err

set -uo pipefail
module reset

# ------------------------------------------------------------------ locations
SCRATCH="${SCRATCH:-$(ls -d /work/hdd/*/"$USER" 2>/dev/null | head -1)}"
[[ -n "$SCRATCH" ]] || { echo "ERROR: no scratch dir found" >&2; exit 1; }
SIF="$SCRATCH/containers/vllm-openai.sif"
export HF_HOME="$SCRATCH/hf"
export HF_HUB_OFFLINE=1          # weights are pre-staged; never hit the network here
export VLLM_WORKER_MULTIPROC_METHOD=spawn
export OMP_NUM_THREADS=8

[[ -f "$SIF" ]] || { echo "ERROR: container missing at $SIF (run hpc/prefetch.slurm)" >&2; exit 1; }

# --------------------------------------------------------------- tunable args
MODEL="Qwen/Qwen3.5-397B-A17B-FP8"
SERVED_NAME="qwen3.5-397b"
MAX_LEN=32768
GPU_UTIL=0.92
# Text-only benchmark: dropping the vision tower frees memory for KV cache.
# Tool calling is mandatory -- sysrepair-bench is entirely tool-driven, and
# without these two flags every request 400s.
EXTRA_ARGS="--language-model-only --enable-auto-tool-choice --tool-call-parser hermes --enable-prefix-caching"

# Runtime override hook: edit ~/hpc/vllm_args.env while this job is queued.
ARGS_FILE="$HOME/hpc/vllm_args.env"
if [[ -f "$ARGS_FILE" ]]; then
  echo "[config] sourcing $ARGS_FILE"
  # shellcheck disable=SC1090
  source "$ARGS_FILE"
else
  echo "[config] no $ARGS_FILE, using baked-in defaults"
fi

# Parallelism follows the GPU count Slurm actually gave us. 8 GPUs -> plain TP,
# the only layout upstream certifies for this model. 4 GPUs -> data-parallel
# attention + expert-parallel MoE, because vLLM issue #34893 reports -tp 4
# failing on exactly 4x H200 with a fused linear layer sharding error.
NGPU="${SLURM_GPUS_ON_NODE:-4}"
if [[ -z "${PARALLEL_ARGS:-}" ]]; then
  if [[ "$NGPU" -ge 8 ]]; then
    PARALLEL_ARGS="-tp 8"
  else
    PARALLEL_ARGS="-dp $NGPU --enable-expert-parallel"
  fi
fi

# ------------------------------------------------------------------ endpoint
PORT=$(( 20000 + (SLURM_JOB_ID % 20000) ))
NODE="$(hostname -s)"
API_KEY="$(openssl rand -hex 24)"

CONN_DIR="$HOME/.vllm_delta"
mkdir -p "$CONN_DIR"; chmod 700 "$CONN_DIR"
CONN_FILE="$CONN_DIR/conn_${SLURM_JOB_ID}.env"
umask 077
cat > "$CONN_FILE" <<EOF
VLLM_JOB_ID=${SLURM_JOB_ID}
VLLM_NODE=${NODE}
VLLM_PORT=${PORT}
VLLM_API_KEY=${API_KEY}
VLLM_SERVED_NAME=${SERVED_NAME}
EOF
chmod 600 "$CONN_FILE"

echo "=============================================================="
echo " job    : ${SLURM_JOB_ID}   node: ${NODE}   port: ${PORT}"
echo " gpus   : ${NGPU}   parallel: ${PARALLEL_ARGS}"
echo " model  : ${MODEL} -> '${SERVED_NAME}'"
echo " extra  : ${EXTRA_ARGS}"
echo " conn   : ${CONN_FILE}"
echo "=============================================================="
nvidia-smi --query-gpu=index,name,memory.total --format=csv,noheader

# --host 0.0.0.0 is required: the SSH tunnel terminates on a login node, which
# reaches this process over the cluster network. Compute nodes are not publicly
# routable; --api-key is the access control on top of that.
# shellcheck disable=SC2086
apptainer exec --nv \
  --bind "$SCRATCH:$SCRATCH" \
  --env "HF_HOME=$HF_HOME" \
  --env "HF_HUB_OFFLINE=1" \
  "$SIF" \
  vllm serve "$MODEL" \
    --served-model-name "$SERVED_NAME" \
    --host 0.0.0.0 --port "$PORT" \
    --api-key "$API_KEY" \
    --gpu-memory-utilization "$GPU_UTIL" \
    --max-model-len "$MAX_LEN" \
    $PARALLEL_ARGS $EXTRA_ARGS &
VLLM_PID=$!
trap 'kill "$VLLM_PID" 2>/dev/null || true' TERM INT EXIT

echo "[wait] polling /health"
for _ in $(seq 1 400); do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    echo "=============================================================="
    echo " READY  ssh -O forward -L 127.0.0.1:8001:${NODE}:${PORT} delta"
    echo " key in ${CONN_FILE}"
    echo "=============================================================="
    break
  fi
  # A wedged or OOM'd vLLM keeps the allocation alive and looks identical to
  # "still loading" if you only watch Slurm, so check the process too.
  kill -0 "$VLLM_PID" 2>/dev/null || { echo "ERROR: vllm exited during startup" >&2; exit 1; }
  sleep 10
done

wait "$VLLM_PID"
