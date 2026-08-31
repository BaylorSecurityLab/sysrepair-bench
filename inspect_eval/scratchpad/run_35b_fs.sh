#!/usr/bin/env bash
# Qwen3.5-35B-A3B full suite on the local L40s: day1 then zero_day, sequentially.
# Sequential on purpose: both legs share one vLLM endpoint, so running them
# together would just split the same decode capacity and double every episode's
# wall-clock without finishing either leg sooner.
cd /home/resbears/projects/sysrepair-bench/inspect_eval
set -a; . ./.env >/dev/null 2>&1; set +a
Y=panelB/qwen35b_fullsuite.runs.yaml

echo "[35b] waiting for vLLM :8100 to serve the 35B ..."
for i in $(seq 1 360); do
  m=$(curl -s --max-time 4 http://localhost:8100/v1/models 2>/dev/null | grep -o '35B-A3B' | head -1)
  [ -n "$m" ] && { echo "[35b] READY after ~$((i*10))s"; break; }
  st=$(docker inspect -f '{{.State.Status}}' pbvllm 2>/dev/null || echo missing)
  if [ "$st" = "exited" ] || [ "$st" = "dead" ]; then
    echo "[35b] SERVE CONTAINER $st -- aborting"; docker logs pbvllm 2>&1 | tail -25; exit 1
  fi
  sleep 10
done
curl -s --max-time 5 http://localhost:8100/v1/models | head -c 300; echo

for leg in qwen35b_fs_day1 qwen35b_fs_zeroday; do
  echo "[35b] === $leg starting $(date -u +%FT%TZ) ==="
  SR_EVAL_SET=1 .venv/bin/python3 -m sysrepair_bench.run "$leg" --runs "$Y" \
    >> scratchpad/${leg}.log 2>&1
  echo "[35b] === $leg exited rc=$? $(date -u +%FT%TZ) ==="
done
echo "[35b] ALL DONE $(date -u +%FT%TZ)"
