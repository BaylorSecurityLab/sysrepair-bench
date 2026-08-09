#!/bin/bash
# Stage everything the H200 serve job needs, on a cheap CPU node.
#
#   sbatch --account=beri-delta-gpu hpc/prefetch.slurm
#
# Why this exists as a separate job:
#   1. The site container (llmflux 1.0.0) ships vLLM 0.15.0, which does NOT know
#      `Qwen3_5MoeForConditionalGeneration` -- the architecture Qwen3.5-397B
#      actually declares. We need our own, newer image.
#   2. The FP8 checkpoint is ~400 GB. Downloading that on an H200 allocation
#      would burn the scarcest resource on the machine doing pure I/O, and
#      downloading it on a login node is exactly what the process killer exists
#      to stop.
#
# Consumes ~415 GB of the /work/hdd/beri 1000 GB project quota.

# NOTE: this asks for 1 GPU it will not use. beri-delta-gpu is a GPU-type
# account and Delta rejects CPU-only jobs from it ("Jobs requesting no GPU
# resources must be submitted under CPU type accounts"), and no CPU account
# exists on this allocation. gpuA40x4 is the cheapest GPU partition
# (charge factor 0.5) and had ~94 free GPUs, so this schedules immediately.
#SBATCH --job-name=vllm-prefetch
#SBATCH --partition=gpuA40x4
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --gpus-per-node=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=64g
#SBATCH --time=08:00:00
#SBATCH --constraint="scratch"
#SBATCH --no-requeue
#SBATCH --output=slurm-prefetch-%j.out
#SBATCH --error=slurm-prefetch-%j.err

set -euo pipefail
module reset

MODEL="${VLLM_MODEL:-Qwen/Qwen3.5-397B-A17B-FP8}"
IMAGE="${VLLM_IMAGE:-docker://vllm/vllm-openai:latest}"

# $SCRATCH/$WORK are unset on Delta and the real path is project-scoped.
SCRATCH="${SCRATCH:-$(ls -d /work/hdd/*/"$USER" 2>/dev/null | head -1)}"
[[ -n "$SCRATCH" ]] || { echo "ERROR: no /work/hdd/<project>/$USER" >&2; exit 1; }

export HF_HOME="$SCRATCH/hf"
export APPTAINER_CACHEDIR="$SCRATCH/apptainer-cache"
export HF_HUB_ENABLE_HF_TRANSFER=0   # plain requests; hf_transfer is not in the base image
SIF="$SCRATCH/containers/vllm-openai.sif"
mkdir -p "$HF_HOME" "$APPTAINER_CACHEDIR" "$SCRATCH/containers"

echo "scratch : $SCRATCH"
echo "model   : $MODEL"
echo "image   : $IMAGE -> $SIF"
df -h "$SCRATCH" | tail -1

# Fail fast if compute nodes have no egress, rather than after a long partial pull.
echo "=== egress check ==="
curl -fsS -o /dev/null -w "huggingface.co http=%{http_code}\n" \
  https://huggingface.co/api/models/Qwen/Qwen2.5-7B-Instruct \
  || { echo "ERROR: no outbound HTTPS from this compute node." >&2; exit 1; }

echo "=== 1/3 pull container ==="
if [[ -f "$SIF" ]]; then
  echo "already present, skipping"
else
  apptainer pull "$SIF" "$IMAGE"
fi
ls -lh "$SIF"

echo "=== 2/3 verify the image knows this architecture ==="
# Cheaper to find out here than after queueing hours for H200.
# NOTE: the vllm/vllm-openai image has python3 but NO `python` on PATH.
apptainer exec "$SIF" python3 -c "
from vllm.model_executor.models.registry import ModelRegistry
import vllm
archs = set(ModelRegistry.get_supported_archs())
want = 'Qwen3_5MoeForConditionalGeneration'
print('vllm', vllm.__version__)
print(want, 'supported:', want in archs)
raise SystemExit(0 if want in archs else 1)
"

echo "=== 3/3 download weights (~400 GB, resumable) ==="
apptainer exec --bind "$HF_HOME:$HF_HOME" --env "HF_HOME=$HF_HOME" "$SIF" python3 -c "
from huggingface_hub import snapshot_download
# ignore_patterns keeps us from also pulling duplicate original-format weights
# that some Qwen repos ship alongside the safetensors shards.
p = snapshot_download('$MODEL', max_workers=8,
                      ignore_patterns=['original/*', '*.pth', '*.gguf'])
print('cached at', p)
"

echo "=== done ==="
du -sh "$HF_HOME" "$SIF"
