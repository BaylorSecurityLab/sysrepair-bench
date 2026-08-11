#!/bin/bash
# kimi_run_all.sh [concurrency]
# Runs Kimi-K3 over all 40 meta2 scenarios × 10 independent epochs (5-attempt
# loop each) with a concurrency cap. Resumable: skips (scenario,epoch) already
# recorded as done in results/results.csv.
set -u
KE=/home/resbears/projects/sysrepair-bench/scripts/kimi-eval
cd "$KE"
CONC="${1:-2}"
[ -f results/results.csv ] || echo "scenario,epoch,attempt_passed,security,regression,joint,status" > results/results.csv

done_ep(){ awk -F, -v s="$1" -v e="$2" '$1==s && $2==e && $7=="done"{ok=1} END{exit ok?0:1}' results/results.csv; }
running(){ pgrep -f "kimi_episode.sh " | grep -v grep | wc -l; }

for n in $(seq -w 1 40); do
  [ -d "/home/resbears/projects/sysrepair-bench/meta2/scenario-$n" ] || continue
  for ep in $(seq 1 3); do
    if done_ep "$n" "$ep"; then echo "[skip] $n e$ep (done)"; continue; fi
    while [ "$(running)" -ge "$CONC" ]; do sleep 5; done
    echo "[$(date -u +%H:%M:%S)] launch $n e$ep"
    bash bin/kimi_episode.sh "$n" "$ep" >>"runs/ep-$n-e$ep.log" 2>&1; rc=$?
    if [ "$rc" = 77 ]; then echo "[HALT] API usage-limit hit at $n e$ep — stop and top up the Kimi subscription, then re-run (resumable)."; exit 77; fi
    sleep 1
  done
done
while [ "$(running)" -gt 0 ]; do sleep 10; done
echo "[$(date -u +%H:%M:%S)] KIMI RUN COMPLETE"
