#!/usr/bin/env python3
"""Live event count for a stream, from inspect's sample buffer. Prints "<n>".

WHY THIS EXISTS
Every liveness signal the supervisor had is too coarse to separate "working on a
long episode" from "wedged":

  * CPU delta separates blocked from busy, but not USEFUL busy from useless busy
    (a retry storm burns CPU at a healthy rate while scoring nothing).
  * The scored-sample count only increments when an EPISODE COMPLETES. meta4 and
    black-box episodes legitimately run 15-50 minutes, so a healthy stream is
    routinely static for a supervisor tick or eight.

The sample buffer at ~/.local/share/inspect_ai/samplebuffer/<hash>/<eval>.<pid>.db
is written continuously as tool calls and model responses land, so its `events`
table increments on the order of seconds. Measured on a live MiniMax stream that
had been scored-static for two hours: +27 events and +155 KB in 60 seconds. That
stream was working; scored count could not tell, and this can.

NOT A RECOVERY PATH. The buffer holds only IN-FLIGHT samples: completed ones are
flushed to the .eval and dropped. The buffer for the run that lost 288 episodes
held 9 samples in 37 MB, all in flight at kill time. Do not mistake a large .db
for recoverable work.
"""
from __future__ import annotations

import glob
import os
import sqlite3
import sys

BUF = os.path.expanduser("~/.local/share/inspect_ai/samplebuffer")


def main() -> None:
    logdir = sys.argv[1]
    evals = glob.glob(f"logs_es/{logdir}/*.eval")
    if not evals:
        print(0)
        return
    stem = os.path.basename(max(evals, key=os.path.getmtime))
    dbs = glob.glob(f"{BUF}/*/{stem}.*.db")
    if not dbs:
        print(0)
        return
    total = 0
    for db in dbs:
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            total += con.execute("select count(*) from events").fetchone()[0]
            con.close()
        except Exception:
            continue
    print(total)


if __name__ == "__main__":
    main()
