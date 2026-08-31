#!/usr/bin/env bash
# Waits for Delta job 21665519 (vllm-q122) to serve, tunnels :8001 to it, then
# runs the 122B full suite: day1 then zero_day.
#
# ssh needs an EXPLICIT ControlPath: the config's ControlPath ~/.ssh/cm-delta-%r
# does not match the live socket at ~/.ssh/cm-delta, so plain `ssh delta` misses
# the master and fails without a Duo push.
cd /home/resbears/projects/sysrepair-bench/inspect_eval
set -a; . ./.env >/dev/null 2>&1; set +a
CM="-o BatchMode=yes -o ControlPath=/home/resbears/.ssh/cm-delta -o ConnectTimeout=20"
JOB=21665519
say(){ echo "[$(date -u +%H:%M:%S)] $*"; }
say "watching Delta job $JOB"

CONN=""
for i in $(seq 1 2880); do    # up to ~48h at 60s, the queue is 385 deep
  st=$(ssh $CM delta "squeue -j $JOB -h -o %T" 2>/dev/null)
  if [ "$st" = "RUNNING" ]; then
    CONN=$(ssh $CM delta "cat ~/.vllm_delta/conn_${JOB}.env 2>/dev/null" 2>/dev/null)
    [ -n "$CONN" ] && break
  elif [ -z "$st" ]; then
    say "job $JOB no longer queued (finished or cancelled); abort"; exit 1
  fi
  [ $((i % 30)) -eq 0 ] && say "still $st"
  sleep 60
done
[ -z "$CONN" ] && { say "no conn file; abort"; exit 1; }

NODE=$(echo "$CONN" | grep -oP 'VLLM_NODE=\K\S+')
PORT=$(echo "$CONN" | grep -oP 'VLLM_PORT=\K\S+')
KEY=$(echo  "$CONN" | grep -oP 'VLLM_API_KEY=\K\S+')
say "serving on $NODE:$PORT"

for i in $(seq 1 120); do     # 122B load from scratch is slow
  h=$(ssh $CM delta "curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://${NODE}:${PORT}/health" 2>/dev/null)
  [ "$h" = "200" ] && { say "vLLM healthy on compute node"; break; }
  [ $((i % 10)) -eq 0 ] && say "loading (health=$h)"
  sleep 30
done

ssh $CM -N -f -L 127.0.0.1:8001:${NODE}:${PORT} delta 2>/dev/null
sleep 5
lh=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "Authorization: Bearer $KEY" http://localhost:8001/health 2>/dev/null)
say "local :8001 health=$lh"
[ "$lh" != "200" ] && { say "tunnel unhealthy; abort"; exit 1; }

export DELTA_VLLM_KEY="$KEY"
for leg in qwen122b_fs_day1 qwen122b_fs_zeroday; do
  say "=== $leg starting ==="
  SR_EVAL_SET=1 .venv/bin/python3 -m sysrepair_bench.run "$leg" \
    --runs panelB/qwen122b_fullsuite.runs.yaml >> scratchpad/${leg}.log 2>&1
  say "=== $leg exited rc=$? ==="
done
say "122B ALL DONE"
