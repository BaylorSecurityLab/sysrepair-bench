#!/bin/bash
# Pull a specific vLLM container image and verify it is usable on Delta.
#
#   VLLM_IMAGE=docker://vllm/vllm-openai:v0.26.0-cu129 \
#   VLLM_SIF_NAME=vllm-openai-cu129.sif \
#     sbatch --account=beri-delta-gpu --export=ALL hpc/pull_container.slurm
#
# Why a specific tag: `vllm/vllm-openai:latest` ships torch 2.11.0+cu130
# (CUDA 13.0) and every worker dies on Delta with
#   "The NVIDIA driver on your system is too old (found version 12080)"
# Delta's driver is CUDA 12.8. CUDA minor-version compatibility carries a 12.9
# build onto a 12.8 driver -- the site llmflux container is torch 2.9.1+cu129
# and runs fine -- but crossing to major version 13 does not work.
#
# Requests 1 GPU it barely uses: beri-delta-gpu is a GPU-type account and Delta
# rejects CPU-only jobs from it. The GPU is genuinely needed here anyway, to
# prove torch can actually initialise CUDA rather than merely import.

#SBATCH --job-name=vllm-pull
#SBATCH --partition=gpuA40x4
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --gpus-per-node=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=64g
#SBATCH --time=01:00:00
#SBATCH --constraint="scratch"
#SBATCH --no-requeue
#SBATCH --output=slurm-pull-%j.out
#SBATCH --error=slurm-pull-%j.err

set -euo pipefail
module reset

IMAGE="${VLLM_IMAGE:-docker://vllm/vllm-openai:v0.26.0-cu129}"
SIF_NAME="${VLLM_SIF_NAME:-vllm-openai-cu129.sif}"

SCRATCH="${SCRATCH:-$(ls -d /work/hdd/*/"$USER" 2>/dev/null | head -1)}"
export APPTAINER_CACHEDIR="$SCRATCH/apptainer-cache"
SIF="$SCRATCH/containers/$SIF_NAME"
mkdir -p "$SCRATCH/containers" "$APPTAINER_CACHEDIR"

echo "image : $IMAGE"
echo "sif   : $SIF"
nvidia-smi --query-gpu=name,driver_version --format=csv,noheader

echo "=== pull ==="
apptainer pull --force "$SIF" "$IMAGE"
ls -lh "$SIF"

echo "=== verify: CUDA actually initialises on this driver ==="
# The whole point of the exercise. `import torch` succeeds even on a mismatched
# build; torch.zeros(...).cuda() is what actually exercises the driver, which is
# where the cu130 image failed.
cat > /tmp/verify_cuda.py <<'PY'
import torch, vllm
from vllm.model_executor.models.registry import ModelRegistry
print("vllm      ", vllm.__version__)
print("torch     ", torch.__version__, "built for CUDA", torch.version.cuda)
print("cuda avail", torch.cuda.is_available())
x = torch.zeros(1024, 1024, device="cuda")
y = (x + 1).sum().item()
print("gpu compute OK, sum =", y)
print("device    ", torch.cuda.get_device_name(0))
want = "Qwen3_5MoeForConditionalGeneration"
ok = want in set(ModelRegistry.get_supported_archs())
print(want, "supported:", ok)
raise SystemExit(0 if ok else 1)
PY
apptainer exec --nv "$SIF" python3 /tmp/verify_cuda.py

echo "=== done: $SIF is usable ==="
