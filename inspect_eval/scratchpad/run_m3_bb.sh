#!/usr/bin/env bash
# MiniMax-M3 BLACK-BOX on the four suites its row is missing:
# vulnhub, ccdc, meta3/ubuntu, sr-modern(meta4). meta2 BB is already complete
# (40 scenarios at E=3, folded as 55.3) and is not in this preset.
#
# SR_EVAL_SET=1 is load-bearing here, not cosmetic: MiniMax quota is a rolling
# window shared with the Windows peer, so this WILL be interrupted mid-suite.
# eval_set makes the next invocation resume the incomplete (model,mode,k) legs
# instead of restarting them.
#
# API-only, so it does not touch the L40s and runs alongside the 35B full-suite.
cd /home/resbears/projects/sysrepair-bench/inspect_eval
set -a; . ./.env >/dev/null 2>&1; set +a
echo "[m3bb] start $(date -u +%FT%TZ)"
SR_EVAL_SET=1 .venv/bin/python3 -m sysrepair_bench.run minimax_fs_zeroday \
  --runs panelB/minimax_fs_zeroday.runs.yaml >> scratchpad/minimax_fs_zeroday.log 2>&1
echo "[m3bb] exited rc=$? $(date -u +%FT%TZ)"
