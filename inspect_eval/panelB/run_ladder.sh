#!/bin/bash
# Sequential Qwen3.5 scale ladder with a WITHIN-FAMILY CASCADE.
#
# The first rung (4B) runs all 40 meta2 scenarios (both modes). Every rung
# after it runs ONLY the scenarios the previous rung failed (>= 1 epoch not
# solved) — the scenarios the previous rung aced (pass@5 == 100% over all 10
# epochs) are imputed as passes and skipped, since a larger same-family model
# almost never regresses on what a smaller one fully solved. This shrinks the
# run set monotonically down the ladder and saves most of the GPU time.
#
# Serve -> (scope) -> run -> stop -> next. Detached; logs to panelB/.
set -u
cd /home/resbears/projects/sysrepair-bench/inspect_eval

# model : preset : tensor_parallel : extra_serve_args (optional, space-sep)
LADDER=(
  "Qwen/Qwen3.5-4B:panel_b_qwen_4b:2:"
  "Qwen/Qwen3.5-9B:panel_b_qwen_9b:2:"
  "Qwen/Qwen3.5-27B:panel_b_qwen_27b:2:"
  "Qwen/Qwen3.5-35B-A3B:panel_b_qwen_35b_a3b:2:"
  # 122B-A10B (122B total / 10B active MoE) does not fit 2xL40 (96GB) in bf16.
  # fp8 dynamic quant ~halves it; if it still OOMs at 262144 ctx, a 4-bit
  # (AWQ/GPTQ) checkpoint is required — serve.sh will surface the OOM.
  "Qwen/Qwen3.5-122B-A10B:panel_b_qwen_122b_a10b:2:--quantization fp8"
)

prev_model=""   # empty for the first rung => run full
for item in "${LADDER[@]}"; do
  model="${item%%:*}"; rest="${item#*:}"
  preset="${rest%%:*}"; rest="${rest#*:}"
  tp="${rest%%:*}"; extra="${rest#*:}"
  echo "===================================================================="
  echo "[$(date -u +%H:%M:%S)] BEGIN $model  preset=$preset tp=$tp extra='${extra}'"

  # Attach to an in-flight run of this rung (e.g. an orphaned prior ladder's
  # 4B baseline): wait for it rather than re-serving/re-running, then treat it
  # as this rung's result and move on to the cascade.
  if pgrep -f "sysrepair_bench.run ${preset}( |\$)" >/dev/null 2>&1; then
    echo "[$(date -u +%H:%M:%S)] attaching to in-flight $preset; waiting for it to finish"
    while pgrep -f "sysrepair_bench.run ${preset}( |\$)" >/dev/null 2>&1; do sleep 30; done
    echo "[$(date -u +%H:%M:%S)] in-flight $preset finished"
    bash panelB/stop.sh
    prev_model="$model"; continue
  fi

  runs_arg=()   # which runs file + preset scoping to use for this rung
  if [ -n "$prev_model" ]; then
    # Cascade: scope this rung to the previous rung's non-aced scenarios.
    echo "[$(date -u +%H:%M:%S)] cascade: scoping $preset to $prev_model failures"
    prev_tag="${prev_model##*/}"                 # e.g. Qwen3.5-4B
    if uv run python panelB/cascade_prep.py "$prev_tag" "$preset" \
         --out "panelB/cascade_${preset}.runs.yaml" 2> >(tee -a panelB/ladder.log >&2); then
      runs_arg=(--runs "panelB/cascade_${preset}.runs.yaml")
    else
      rc=$?
      if [ "$rc" = 3 ]; then
        echo "[$(date -u +%H:%M:%S)] $prev_model aced all scenarios — SKIP $model (imputed)"
        prev_model="$model"; continue
      fi
      echo "[$(date -u +%H:%M:%S)] cascade prep failed rc=$rc — falling back to FULL run for $model"
    fi
  fi

  if ! bash panelB/serve.sh "$model" "$tp" $extra; then
     echo "[$(date -u +%H:%M:%S)] SERVE FAILED for $model — skipping"
     bash panelB/stop.sh; prev_model="$model"; continue
  fi
  echo "[$(date -u +%H:%M:%S)] serving OK; launching meta2 eval for $preset"
  uv run python -m sysrepair_bench.run "$preset" "${runs_arg[@]}" \
      > "panelB/run_${preset}.log" 2>&1
  rc=$?
  echo "[$(date -u +%H:%M:%S)] DONE $preset rc=$rc"
  bash panelB/stop.sh
  sleep 8
  prev_model="$model"
done
echo "[$(date -u +%H:%M:%S)] LADDER COMPLETE"
