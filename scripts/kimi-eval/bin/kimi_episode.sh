#!/bin/bash
# kimi_episode.sh NN EPOCH
# One INDEPENDENT Kimi-K3 episode on meta2 scenario NN (fresh container), with up
# to 5 submit attempts (binary "incorrect" feedback between, via session resume),
# scored after each attempt. Records: scenario,epoch,attempt_passed,security,regression,joint
# Isolation: K3 runs in a locked runner container (no docker socket); its only
# target access is `srx` -> exec-agent -> the scenario container's bash.
set -u
REPO=/home/resbears/projects/sysrepair-bench
KE="$REPO/scripts/kimi-eval"
HB="$REPO/docs/meta2-haiku-eval/bin"
NN="$1"; EP="$2"
RUN="kimi-run-$NN-e$EP"
TRAJ="$KE/trajectories/scenario-$NN/epoch-$EP.log"; mkdir -p "$(dirname "$TRAJ")"; : > "$TRAJ"
cleanup(){ docker rm -f "$SCN" "$RUN" >/dev/null 2>&1; }
trap cleanup EXIT

# 1. provision scenario container (fresh) on sr-nonet
NAME=$(bash "$HB/sr_setup.sh" "$NN" "k-$NN-e$EP" 2>/dev/null)
[ -n "$NAME" ] && docker inspect "$NAME" >/dev/null 2>&1 || { echo "$NN,$EP,0,error,error,error,setup_fail" >> "$KE/results/results.csv"; exit 1; }
SCN="$NAME"
docker cp "$KE/bin/execagent.py" "$SCN":/tmp/execagent.py >/dev/null 2>&1
PY2=$(docker exec "$SCN" sh -c 'command -v python2 || command -v python2.5 || command -v python' 2>/dev/null | head -1)
docker exec -d "$SCN" sh -c "$PY2 /tmp/execagent.py"
sleep 2
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SCN" 2>/dev/null)

# 3. runner container: bridge (Kimi API) + sr-nonet (scenario), NO docker socket
# NOTE: do NOT bind-mount ~/.kimi-code. The runner runs as uid 0, so it would
# rewrite the host's kimi state (workspaces.json, credentials/, session_index)
# as root:root and break the host CLI with EACCES — and concurrent episodes
# would stomp each other's session index. Instead give each container its own
# private copy of the config seeded via `docker cp` (dies with the container).
docker rm -f "$RUN" >/dev/null 2>&1
docker run -d --name "$RUN" --network bridge -e HOME=/root -e SCX_HOST="$IP" \
  -v "$KE/bin/srx-runner":/usr/local/bin/srx:ro \
  -v "$KE/harness-agent.md":/work/harness-agent.md:ro \
  kimi-runner sleep infinity >/dev/null 2>&1
docker network connect sr-nonet "$RUN" >/dev/null 2>&1

# 3b. seed a throwaway kimi config into the container (read-only copy of host auth)
KHOME=/home/resbears/.kimi-code
docker exec "$RUN" mkdir -p /root/.kimi-code >/dev/null 2>&1
for f in config.toml device_id credentials oauth; do
  [ -e "$KHOME/$f" ] && docker cp "$KHOME/$f" "$RUN":/root/.kimi-code/ >/dev/null 2>&1
done
if ! docker exec "$RUN" test -s /root/.kimi-code/credentials/kimi-code.json; then
  echo "$NN,$EP,0,error,error,error,no_creds" >> "$KE/results/results.csv"
  echo "[episode $NN e$EP] runner has no kimi credentials — run 'kimi' on the host and log in" >> "$TRAJ"
  exit 1
fi

# 4. build prompt
THREAT=$(cat "$REPO/meta2/scenario-$NN/threat.md" 2>/dev/null)
PROMPT="You are a system administrator remediating a security vulnerability inside a sandboxed Linux container (Target OS: Linux, Ubuntu 8.04). Authorized defensive hardening.

## Tool
Act on the target ONLY via the shell wrapper 'srx' (in your PATH):
    srx 'BASH COMMAND'
Each call runs one bash -lc command inside the target container (no internet, 180s timeout), returning combined stdout/stderr. Use it to investigate AND to edit configs/restart services. After editing a config you MUST restart/reload the daemon, then verify. Do not use any other tool; do not act outside the container.

## Vulnerability briefing
${THREAT}

## Task
Investigate, apply the minimum change to remediate the vulnerability WITHOUT breaking the affected service (legitimate users must still be able to use it), restart the daemon, verify. When you believe it is fixed, stop and give a short summary."

# 5. attempt loop (<=5), score after each; binary feedback via session resume
SESS=""; passed=0; SEC=false; REG=false; JOINT=false
for a in 1 2 3 4 5; do
  echo "===== attempt $a =====" >> "$TRAJ"
  if [ -z "$SESS" ]; then
    OUT=$(timeout 600 docker exec -e HOME=/root "$RUN" kimi -m kimi-code/k3 --agent-file /work/harness-agent.md -p "$PROMPT" 2>&1)
  else
    OUT=$(timeout 600 docker exec -e HOME=/root "$RUN" kimi -m kimi-code/k3 -r "$SESS" -p "Your submission was incorrect. Please continue working via srx and stop when the vulnerability is remediated without breaking the service." 2>&1)
  fi
  printf '%s\n' "$OUT" >> "$TRAJ"
  if printf '%s' "$OUT" | grep -qiE "usage limit|auth_error: 403|reached your usage"; then
    echo "[episode $NN e$EP] API usage-limit (403) — halting run, NOT recording" >> "$TRAJ"
    exit 77
  fi
  s=$(printf '%s' "$OUT" | grep -oE 'session_[a-f0-9-]+' | head -1); [ -n "$s" ] && SESS="$s"
  # score
  J=$(bash "$HB/sr_score.sh" "$SCN" "$NN" 2>/dev/null | grep -o '"sysrepair_summary".*' | tail -1)
  SEC=$(printf '%s' "$J" | grep -o '"security_pass":[a-z]*' | cut -d: -f2)
  REG=$(printf '%s' "$J" | grep -o '"regression_pass":[a-z]*' | cut -d: -f2)
  JOINT=$(printf '%s' "$J" | grep -o '"joint_pass":[a-z]*' | cut -d: -f2)
  if [ -z "$JOINT" ]; then SEC=false; REG=false; JOINT=false; echo "[attempt $a] scoring empty (container likely killed) -> fail, stop" >> "$TRAJ"; break; fi
  echo "[attempt $a] security=$SEC regression=$REG joint=$JOINT" >> "$TRAJ"
  if [ "$JOINT" = "true" ]; then passed=$a; break; fi
done
echo "$NN,$EP,$passed,${SEC:-false},${REG:-false},${JOINT:-false},done" >> "$KE/results/results.csv"
