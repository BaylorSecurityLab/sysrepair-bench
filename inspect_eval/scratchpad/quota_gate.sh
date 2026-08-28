#!/bin/bash
# Quota gate for MiniMax. Reads the response BODY, not just the status line.
#
# WHY THE BODY: a bare RateLimitError / 429 cannot distinguish "back off and
# retry" from "the account is dry". Our run logs printed RateLimitError eight
# times and it was useless for deciding what to do; only the body's
# "Token Plan usage limit reached ... (2056)" identifies the quota wall.
#
# WHY max_tokens 4096: probing at max_tokens 1 can succeed trivially while the
# real harness load fails. Probe at the size actually sent.
#
# exit 0 = quota OK          -> safe to launch / restart
# exit 2 = QUOTA WALL        -> STOP; a restart cannot manufacture tokens
# exit 1 = other/transient   -> treat as retryable, do not conclude
cd /home/resbears/projects/sysrepair-bench/inspect_eval
set -a; source ./.env; set +a
body=$(curl -s --max-time 30 https://api.minimax.io/v1/chat/completions \
  -H "Authorization: Bearer $MINIMAX_API_KEY" -H 'Content-Type: application/json' \
  -d '{"model":"MiniMax-M3","messages":[{"role":"user","content":"ok"}],"max_tokens":4096}' 2>/dev/null)
case "$body" in
  *'"choices"'*)                      echo "QUOTA-OK";       exit 0 ;;
  *'Token Plan'*|*'(2056)'*)          echo "QUOTA-WALL";     exit 2 ;;
  *)                                  echo "QUOTA-UNKNOWN";  exit 1 ;;
esac
