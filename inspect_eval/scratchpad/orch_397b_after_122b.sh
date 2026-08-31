#!/usr/bin/env bash
# Submits and runs the 397B ONLY AFTER the 122B job 21665519 has finished.
#
# The sequencing is deliberate (user instruction 2026-08-31): running the smaller
# rung first means the remaining Delta allocation is attributable to the 397B
# alone. This script therefore WAITS for 21665519 to leave the queue before it
# submits anything, and never queues the two together.
cd /home/resbears/projects/sysrepair-bench/inspect_eval
set -a; . ./.env >/dev/null 2>&1; set +a
CM="-o BatchMode=yes -o ControlPath=/home/resbears/.ssh/cm-delta -o ConnectTimeout=20"
PREV=21665519
say(){ echo "[$(date -u +%H:%M:%S)] $*"; }

say "waiting for 122B job $PREV to finish before submitting the 397B"
for i in $(seq 1 8640); do          # up to ~6 days at 60s
  st=$(ssh $CM delta "squeue -j $PREV -h -o %T" 2>/dev/null)
  [ -z "$st" ] && { say "job $PREV no longer in queue -> 122B done"; break; }
  [ $((i % 60)) -eq 0 ] && say "122B still $st"
  sleep 60
done

# Point the runtime override at the 397B. vllm_serve.slurm sources this at job
# start, so it can be edited while queued without losing position.
say "switching ~/hpc/vllm_args.env to the 397B"
ssh $CM delta 'cat > ~/hpc/vllm_args.env <<EOF
MODEL="Qwen/Qwen3.5-397B-A17B-FP8"
SERVED_NAME="qwen3.5-397b"
MAX_LEN=32768
GPU_UTIL=0.92
# Text-only benchmark: dropping the vision tower frees memory for KV cache.
# qwen3_xml is mandatory; hermes starts cleanly, passes /health, and parses ZERO
# tool calls, silently wasting the rung.
EXTRA_ARGS="--language-model-only --enable-auto-tool-choice --tool-call-parser qwen3_xml --enable-prefix-caching"
# 8 GPUs -> plain TP, the only layout upstream certifies for this model.
PARALLEL_ARGS="-tp 8"
EOF
echo "--- vllm_args.env ---"; grep -E "MODEL|SERVED|PARALLEL" ~/hpc/vllm_args.env'

JOB=$(ssh $CM delta 'cd ~/hpc && sbatch --account=beri-delta-gpu --gpus-per-node=8 --exclusive --time=48:00:00 --job-name=vllm-q397 vllm_serve.slurm' 2>/dev/null | grep -oE '[0-9]+$')
[ -z "$JOB" ] && { say "sbatch failed"; exit 1; }
say "397B submitted as job $JOB"

CONN=""
for i in $(seq 1 8640); do
  st=$(ssh $CM delta "squeue -j $JOB -h -o %T" 2>/dev/null)
  if [ "$st" = "RUNNING" ]; then
    CONN=$(ssh $CM delta "cat ~/.vllm_delta/conn_${JOB}.env 2>/dev/null" 2>/dev/null)
    [ -n "$CONN" ] && break
  elif [ -z "$st" ]; then say "job $JOB left the queue unexpectedly"; exit 1; fi
  [ $((i % 60)) -eq 0 ] && say "397B still $st"
  sleep 60
done

NODE=$(echo "$CONN" | grep -oP 'VLLM_NODE=\K\S+')
PORT=$(echo "$CONN" | grep -oP 'VLLM_PORT=\K\S+')
KEY=$(echo  "$CONN" | grep -oP 'VLLM_API_KEY=\K\S+')
say "serving on $NODE:$PORT"
for i in $(seq 1 240); do   # 397B load is slow
  h=$(ssh $CM delta "curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://${NODE}:${PORT}/health" 2>/dev/null)
  [ "$h" = "200" ] && { say "healthy on compute node"; break; }
  [ $((i % 10)) -eq 0 ] && say "loading (health=$h)"
  sleep 30
done
ssh $CM -N -f -L 127.0.0.1:8001:${NODE}:${PORT} delta 2>/dev/null
sleep 5
lh=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "Authorization: Bearer $KEY" http://localhost:8001/health 2>/dev/null)
say "local :8001 health=$lh"
[ "$lh" != "200" ] && { say "tunnel unhealthy; abort"; exit 1; }

export DELTA_VLLM_KEY="$KEY"
for leg in qwen397b_fs_day1 qwen397b_fs_zeroday; do
  say "=== $leg starting ==="
  SR_EVAL_SET=1 .venv/bin/python3 -m sysrepair_bench.run "$leg" \
    --runs panelB/qwen397b_fullsuite.runs.yaml >> scratchpad/${leg}.log 2>&1
  say "=== $leg exited rc=$? ==="
done
say "397B ALL DONE"
