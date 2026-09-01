#!/bin/bash
# panelB/serve.sh <HF_MODEL> [tp] [extra vllm args...]
# Brings up vllm-openai on localhost:8100 serving HF_MODEL, waits for /health.
#
# MAX_LEN defaults to 32768, NOT the model's ceiling. Serving Qwen3.5-35B-A3B at
# max-model-len 262144 left KV cache headroom for a maximum concurrency of 2.48x
# while the harness drove 10 connections; after 11 hours a worker stalled, the
# shared-memory broadcast timed out, and EngineCore died with a fatal
# TimeoutError, taking the zero_day leg and a gap-fill run down with it. The same
# 262144 was hard-coded for every locally served model, so it would have recurred
# on the 122B GPTQ rung.
#
# At 32768 the identical 166,848-token cache supports 16.63x concurrency. No
# episode in this benchmark needs a 256k window. Override per model with
#   MAX_LEN=65536 MAX_SEQS=8 panelB/serve.sh <model> 2
set -u
MODEL="$1"; TP="${2:-2}"; shift 2 2>/dev/null || shift $#
EXTRA=("$@")
HF_TOKEN=$(cat /home/resbears/.cache/huggingface/token 2>/dev/null || echo "")
docker rm -f pbvllm >/dev/null 2>&1 || true
echo "[serve] starting vLLM for $MODEL (tp=$TP) on :8100 ..."
docker run -d --name pbvllm --gpus all --shm-size 24g \
  -v /home/resbears/.cache/huggingface:/root/.cache/huggingface \
  -e HF_TOKEN="$HF_TOKEN" -e HUGGING_FACE_HUB_TOKEN="$HF_TOKEN" \
  -p 8100:8000 \
  vllm/vllm-openai:latest \
  --model "$MODEL" --served-model-name "$MODEL" \
  --tensor-parallel-size "$TP" --gpu-memory-utilization 0.92 \
  --max-model-len "${MAX_LEN:-32768}" --max-num-seqs "${MAX_SEQS:-16}" \
  --trust-remote-code \
  --enable-auto-tool-choice --tool-call-parser qwen3_coder --enable-prefix-caching \
  "${EXTRA[@]}" >/dev/null
echo "[serve] container up; waiting for model load + /health (downloads can take a while)..."
for i in $(seq 1 240); do   # up to ~40 min (covers big downloads)
  if curl -s --max-time 4 http://localhost:8100/health >/dev/null 2>&1; then
    echo "[serve] READY after ~$((i*10))s"
    curl -s http://localhost:8100/v1/models | python3 -c "import sys,json;print('[serve] serving:', [m['id'] for m in json.load(sys.stdin)['data']])" 2>/dev/null
    exit 0
  fi
  st=$(docker inspect -f "{{.State.Status}}" pbvllm 2>/dev/null || echo missing)
  if [ "$st" = "exited" ] || [ "$st" = "dead" ]; then
    echo "[serve] CONTAINER $st. Last logs:"; docker logs pbvllm 2>&1 | tail -30; exit 1
  fi
  sleep 10
done
echo "[serve] TIMEOUT waiting for health"; docker logs pbvllm 2>&1 | tail -30; exit 1
