#!/bin/bash
# Dump the real `vllm serve --help` from inside the container, on a GPU node.
#
#   sbatch --account=beri-delta-gpu hpc/probe_flags.slurm
#
# This cannot be done on a login node: vLLM 0.26 builds its argument parser
# from VllmConfig, which calls device detection, which raises
# "Failed to infer device type" when no GPU is present. So the only way to see
# the valid --tool-call-parser / --reasoning-parser choices is to hold a GPU.
#
# One cheap A40 for a couple of minutes buys certainty about flag values before
# committing to the gpuH200x8 queue, which is currently ~5 days deep.

#SBATCH --job-name=vllm-probe
#SBATCH --partition=gpuA40x4
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --gpus-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=32g
#SBATCH --time=00:15:00
#SBATCH --constraint="scratch"
#SBATCH --no-requeue
#SBATCH --output=slurm-probe-%j.out
#SBATCH --error=slurm-probe-%j.err

set -uo pipefail
module reset

SCRATCH="${SCRATCH:-$(ls -d /work/hdd/*/"$USER" 2>/dev/null | head -1)}"
SIF="$SCRATCH/containers/vllm-openai.sif"
OUT="$HOME/vllm_help.txt"

echo "sif: $SIF"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader

# vLLM 0.26 groups its help: bare `--help` prints only the group index, which is
# why an earlier probe reported every flag "missing". --help=all is the real one.
apptainer exec --nv "$SIF" vllm serve --help=all > "$OUT" 2>&1
echo "help lines: $(wc -l < "$OUT")"

echo "=== tool-call-parser choices ==="
grep -A10 -E "^\s*--tool-call-parser" "$OUT" | head -24

echo "=== reasoning-parser choices ==="
grep -A10 -E "^\s*--reasoning-parser" "$OUT" | head -24

echo "=== confirm the flags we plan to pass ==="
for f in --language-model-only --enable-expert-parallel --data-parallel-size \
         --enable-auto-tool-choice --enable-prefix-caching --max-model-len \
         --max-cudagraph-capture-size --gpu-memory-utilization --api-key; do
  if grep -qE -- "$f" "$OUT"; then echo "  OK      $f"; else echo "  MISSING $f"; fi
done

echo "=== full help saved to $OUT ==="
