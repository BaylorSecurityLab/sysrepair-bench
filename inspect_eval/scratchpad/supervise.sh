#!/bin/bash
# Wedge supervisor + completion reporter for all five eval streams.
#
# WHY THIS EXISTS
# A stream can park forever on a half-closed socket: the remote closes, the client
# never does, the first model call never returns, and the process sits in
# CLOSE_WAIT indefinitely. The configured timeouts do NOT save it (all four model_*
# keys set correctly and it still hung), and the harness backstop is
# hang_kill_seconds = max(time_limit*(retry_on_error+2), 1800) = 14400s for our
# presets. A four-hour backstop for a fault detectable in ten minutes is not a
# detector; it is what runs when the detector is missing.
#
# DETECTION (three-signal conjunction; any single term alone is a false positive)
#   1. CPU delta below a THRESHOLD for the tick
#   2. scored-sample count static
#   3. at least one CLOSE_WAIT socket owned by the pid
#
# The CPU term must be a threshold, never exact equality: a blocked process still
# accrues idle-loop CPU, so an equality test never holds and the counter resets
# every tick, reporting a clean state it cannot actually detect.
#
# TWO FIXES over the previous version, both found the hard way:
#  (a) It watched only three streams. The two Qwen-9B legs run against a DELTA
#      TUNNEL, which is precisely the endpoint that can vanish, so they were the
#      ones most needing supervision and were the ones omitted. All five now.
#  (b) The old completion watcher marked a stream permanently "seen" on status
#      =error. After a deliberate kill and relaunch that made it blind to the new
#      run forever. Status is now re-read every tick and only ever reported, never
#      latched, so a relaunched stream is picked up again.
#
# For tunnelled streams the tunnel itself is a term: if :8001 is unreachable the
# 9B legs cannot work regardless of their own state, so that is reported
# separately rather than mistaken for a wedge.
set -uo pipefail
cd /home/resbears/projects/sysrepair-bench/inspect_eval
source .venv/bin/activate

TICK=300
CPU_MIN_DELTA=3
NEED_TICKS=2
STATIC_TICKS=8        # scored-static ticks before reporting (~40 min).
                      # Was 3 (~15 min), which fired on every stream on every
                      # tick during entirely normal operation: a meta4 episode
                      # legitimately runs 15-50 min, and only COMPLETED episodes
                      # increment the count, so gaps that long are the norm and
                      # not a signal. An alert that fires constantly on healthy
                      # behaviour trains the reader to ignore it, which costs
                      # more than the alert is worth. 8 ticks still catches a
                      # genuine multi-hour stall.
MAX_RESTARTS=8

declare -A PREV_CPU PREV_SCORED WEDGED RESTARTS LAST_STATUS STATIC PREV_CW PREV_EV
STREAMS="minimax_fs_day1:panelB/minimax_fs_day1.runs.yaml:minimax_fs_day1_react_day1_k5:0 \
qwen27b_fs_day1:panelB/qwen27b_fullsuite.runs.yaml:qwen27b_fs_day1_react_day1_k5:0 \
qwen27b_fs_zeroday:panelB/qwen27b_fullsuite.runs.yaml:qwen27b_fs_zeroday_react_zero_day_k5:0 \
qwen9b_fs_day1:panelB/qwen9b_fullsuite.runs.yaml:qwen9b_fs_day1_react_day1_k5:1 \
qwen9b_fs_zeroday:panelB/qwen9b_fullsuite.runs.yaml:qwen9b_fs_zeroday_react_zero_day_k5:1"

cpu_secs() { local t="${1:-}"; [ -z "$t" ] && { echo 0; return; }
  echo "$t" | awk -F: '{n=NF;s=0;m=1;for(i=n;i>=1;i--){s+=$i*m;m*=60}print s}'; }

probe() { python3 scratchpad/probe_scored.py "$1" 2>/dev/null || echo "unknown 0"; }
# NOT `|| echo 0`. A crashed probe returning a confident zero is precisely the
# silent-veto-removal this term exists to avoid; "err" means unobservable.
bufev() { python3 scratchpad/buffer_events.py "$1" 2>/dev/null || echo err; }

while true; do
  tunnel=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 http://127.0.0.1:8001/health 2>/dev/null || echo 000)
  ALIVE=0
  for entry in $STREAMS; do
    IFS=: read -r name yaml logdir tunnelled <<<"$entry"
    # Select the REAL python process, not the "uv run" wrapper that also matches.
    # The wrapper accrues ~0 CPU forever, so measuring it makes the CPU term
    # permanently look like a wedge, which is the same class of silent-misread
    # that the exact-equality test had.
    pid=$(pgrep -f "\.venv/bin/python3 -m sysrepair_bench.run $name" | tail -1)
    [ -z "$pid" ] && pid=$(pgrep -f "sysrepair_bench.run $name" | tail -1)
    read -r st scored <<<"$(probe "$logdir")"

    if [ -z "$pid" ]; then
      if [ "${LAST_STATUS[$name]:-}" != "gone-$st" ]; then
        echo "STOPPED $name (status=$st scored=$scored)"
        LAST_STATUS[$name]="gone-$st"
      fi
      continue
    fi
    ALIVE=1
    [ "${LAST_STATUS[$name]:-}" = "gone-$st" ] && LAST_STATUS[$name]=""

    if [ "$tunnelled" = "1" ] && [ "$tunnel" != "200" ]; then
      echo "TUNNEL-DOWN $name (:8001 health=$tunnel) - cannot progress, not a wedge"
      PREV_SCORED[$name]=-1; WEDGED[$name]=0; continue
    fi

    # LIVE-WORK TERM. Events in inspect's sample buffer increment on every tool
    # call and model response, so they move on the order of seconds, whereas the
    # scored count only moves when a whole episode finishes (15-50 min for meta4
    # and black-box). Measured on a MiniMax stream scored-static for two hours:
    # +27 events in 60s. It was working. This is the term that can say so, and
    # its absence is what let a "110 minutes with no output" read as dead and
    # cost 288 banked episodes to a needless restart.
    #
    # The probe returns "none"/"err" when it CANNOT OBSERVE, never 0. That
    # distinction is load-bearing here because this term is a VETO: if a
    # mis-resolved path made it report a confident zero, the veto would evaluate
    # as "no work happening" every tick, the protection would silently vanish,
    # and the supervisor would revert to exactly the behaviour that destroyed 288
    # episodes. So an unobservable buffer SUPPRESSES the wedge and says so out
    # loud, rather than quietly permitting one. A missed wedge costs idle time; a
    # wrong restart costs irreplaceable work, and the asymmetry decides the
    # default.
    ev=$(bufev "$logdir")
    if [ "$ev" = "none" ] || [ "$ev" = "err" ]; then
      ev_ok=0; dev=0
      if [ "${LAST_STATUS[buf-$name]:-}" != "$ev" ]; then
        echo "BUFFER-UNREADABLE $name ($ev) - live-work term unavailable, wedge detection SUPPRESSED for this stream until it resolves"
        LAST_STATUS[buf-$name]="$ev"
      fi
    else
      ev_ok=1; LAST_STATUS[buf-$name]=""
      pev=${PREV_EV[$name]:--1}; dev=$(( ev - (pev<0?ev:pev) ))
      PREV_EV[$name]=$ev
    fi
    cpu=$(cpu_secs "$(ps -o cputime= -p "$pid" 2>/dev/null | tr -d ' ')")
    cw=$(ss -tnp state close-wait 2>/dev/null | grep -c "pid=$pid" || true)
    pc=${PREV_CPU[$name]:-0}; ps_=${PREV_SCORED[$name]:--1}
    dcpu=$(( cpu - pc ))
    PREV_CPU[$name]=$cpu; PREV_SCORED[$name]=$scored

    # MONOTONICITY: THE ONLY RELIABLE DETECTOR OF DESTRUCTIVE LOSS.
    # A relaunched eval_set dir is NOT guaranteed to be a superset of the work
    # done: a peer reproduced backup=23 / live=18 with a UNION of 28, so the live
    # dir had both lost and gained episodes. A cell folded from live alone can be
    # silently SHORT with a clean denominator and no error anywhere.
    #
    # The deduped scored count must never DECREASE. That is the whole test. It
    # needs no backup, no expected grid, and it catches loss of any size.
    #
    # It replaces a check I had wrong: "expected - scored == sum of shortfalls"
    # is an ALGEBRAIC IDENTITY, since Sum_seen(E - len_s) + (S-seen)*E reduces to
    # expected - scored. Both sides are one quantity written twice, so it can
    # never fail. Verified: dropping 40 random episodes still reconciles.
    hw_file="scratchpad/scored_highwater"
    hw=$(grep -E "^$name " "$hw_file" 2>/dev/null | tail -1 | awk '{print $2}')
    hw=${hw:-0}
    if [ "$scored" -lt "$hw" ]; then
      echo "*** EPISODE LOSS $name: scored=$scored is BELOW high-water $hw. A relaunch has replaced .eval files. Restore from logs_backup/ and fold from the UNION of every copy, not from live. ***"
    else
      if [ "$scored" -gt "$hw" ]; then
        grep -v -E "^$name " "$hw_file" 2>/dev/null > "$hw_file.tmp" || true
        echo "$name $scored" >> "$hw_file.tmp"
        mv "$hw_file.tmp" "$hw_file"
      fi
    fi

    # FOURTH STATE: RETRY STORM. A run that is rate-limited burns CPU at a
    # healthy rate while scoring NOTHING, so every CPU-based liveness term reads
    # it as fine. Observed live: scored stuck for 1h45m at 5.8-6.8 CPU-s/tick
    # with wedged=0 every tick. CPU can only separate blocked from busy; it
    # cannot separate USEFUL busy from USELESS busy. Only the sample count can
    # see it, and only the response BODY can say why. So scored-static alone,
    # regardless of CPU or close_wait, triggers a quota probe.
    if [ "$ps_" != "-1" ] && [ "$scored" = "$ps_" ]; then
      STATIC[$name]=$(( ${STATIC[$name]:-0} + 1 ))
    else
      STATIC[$name]=0
    fi
    # The quota gate probes MINIMAX. Only a MiniMax-backed stream may be judged
    # by it. Applying it to a locally-served or Delta-served stream concludes
    # something the probe cannot observe: a slow local black-box episode was
    # killed here because a DIFFERENT provider was dry. Guard on provider.
    # CLOSE_WAIT AS A QUOTA PRECURSOR (peer finding, 2026-08-28). On the Windows
    # box a persistent CLOSE_WAIT on a MiniMax stream preceded confirmed
    # exhaustion twice (onsets 09:43 and 16:48), and it clears on restart then
    # re-develops, so it tracks the ACCOUNT, not the platform. That makes it an
    # early warning available BEFORE the scored count has gone static for 40
    # minutes. Probe quota on either signal, not on scored-static alone.
    cw_persist=0
    if [ "$cw" -ge 1 ] && [ "${PREV_CW[$name]:-0}" -ge 1 ]; then cw_persist=1; fi
    PREV_CW[$name]=$cw
    if { [ "${STATIC[$name]:-0}" -ge "$STATIC_TICKS" ] || [ "$cw_persist" = "1" ]; } \
       && [ "${name#minimax}" != "$name" ]; then
      bash scratchpad/quota_gate.sh >/dev/null 2>&1; q=$?
      if [ "$q" = "2" ]; then
        echo "QUOTA-WALL $name - scored static ${STATIC[$name]} ticks at $scored, endpoint exhausted. Stopping, not restarting."
        kill -INT "$pid" 2>/dev/null
        STATIC[$name]=0; WEDGED[$name]=0; continue
      else
        echo "PROBED $name - static=${STATIC[$name]} cw_persist=$cw_persist at $scored, quota OK"
        STATIC[$name]=0
      fi
    elif [ "${STATIC[$name]:-0}" -ge "$STATIC_TICKS" ]; then
      # Non-MiniMax stream: report the stall, take NO action. Long black-box
      # episodes legitimately go many ticks without scoring.
      if [ "${LAST_STATUS[static-$name]:-}" != "$scored" ]; then
        echo "STATIC $name - $scored unchanged for ${STATIC[$name]} ticks, but +$dev buffer events this tick (working, long episodes; ev_ok=$ev_ok)"
        LAST_STATUS[static-$name]="$scored"   # latch: re-report only on a NEW stuck value
      fi
      STATIC[$name]=0
    fi

    if [ "$ps_" != "-1" ] && [ "$ev_ok" = "1" ] && [ "$dcpu" -lt "$CPU_MIN_DELTA" ] && [ "$scored" = "$ps_" ] && [ "$cw" -ge 1 ] && [ "$dev" -le 0 ]; then
      WEDGED[$name]=$(( ${WEDGED[$name]:-0} + 1 ))
      echo "WEDGE-SUSPECT $name tick=${WEDGED[$name]} dcpu=${dcpu}s scored=$scored cw=$cw dev=$dev"
    else
      [ "${WEDGED[$name]:-0}" -gt 0 ] && echo "RECOVERED $name (dcpu=${dcpu}s scored=$scored cw=$cw)"
      WEDGED[$name]=0
    fi

    if [ "${WEDGED[$name]:-0}" -ge "$NEED_TICKS" ]; then
      r=${RESTARTS[$name]:-0}
      if [ "$r" -ge "$MAX_RESTARTS" ]; then
        echo "GIVING UP $name after $r restarts - needs a human"; WEDGED[$name]=0; continue
      fi
      # QUOTA GATE. A wedge-restart against a drained account is the worst
      # possible behaviour: it burns wall-clock, produces nothing, and looks like
      # activity. Re-probe before every restart and read the BODY, since a bare
      # RateLimitError cannot separate "back off" from "the account is dry".
      if [ "$name" = "minimax_fs_day1" ]; then
        bash scratchpad/quota_gate.sh >/dev/null 2>&1; q=$?
        if [ "$q" = "2" ]; then
          echo "QUOTA-WALL $name - 429 Token Plan exhausted, NOT a wedge. Stopping, not restarting."
          WEDGED[$name]=0; continue
        fi
      fi
      # AUTO-RESTART DISABLED 2026-08-28. Relaunching an eval_set stream can
      # REPLACE its .eval files rather than append: a MiniMax restart today
      # destroyed 288 banked episodes (32MB of logs became 750KB / 7 scored).
      # A restart is therefore not a cheap, reversible action on these runs, and
      # a threshold must not be allowed to take it. Report only; a human decides,
      # and copies the log dir first.
      echo "WEDGE-CONFIRMED $name (scored=$scored) - NOT restarting. Auto-restart is disabled: a relaunch can replace banked .eval files. Back up logs_es/$logdir before any manual restart."
      WEDGED[$name]=0
      continue
      echo "RESTARTING $name (wedged, restart $((r+1))/$MAX_RESTARTS, scored=$scored banked)"
      kill -INT "$pid" 2>/dev/null; sleep 20; kill -9 "$pid" 2>/dev/null; sleep 5
      set -a; source ./.env; set +a
      setsid nohup env SR_EVAL_SET=1 uv run python -m sysrepair_bench.run "$name" --runs "$yaml" \
        >> "scratchpad/$name.log" 2>&1 < /dev/null &
      RESTARTS[$name]=$((r+1)); WEDGED[$name]=0; PREV_SCORED[$name]=-1
      echo "RELAUNCHED $name"
    fi
  done
  [ "$ALIVE" = "0" ] && { echo "NO STREAMS ALIVE - supervisor exiting"; exit 0; }
  sleep "$TICK"
done
