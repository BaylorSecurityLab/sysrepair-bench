#!/usr/bin/env python3
"""Live event count for a stream, from inspect's sample buffer.

Prints one token:
    <n>      events currently in the buffer(s) for this stream's newest .eval
    none     NO buffer file found (cannot observe)
    err      a buffer exists but could not be read (cannot observe)

WHY "none"/"err" ARE NOT 0
An instrument must be able to say "I could not observe" separately from "I
observed nothing". This probe is used as a VETO: a wedge requires, among other
things, that the buffer is NOT growing. If a mis-resolved path made the probe
return 0, the veto would silently evaluate as "no work happening" on every tick,
the protection would vanish, and the supervisor would quietly revert to the
behaviour that destroyed 288 banked episodes. The safety term must not fail into
the unsafe state without saying so. (Peer hit exactly this on Windows: running
from WSL with a Windows path printed a clean, confident zero.)

WHY THIS EXISTS AT ALL
Every other liveness signal is too coarse to separate a long episode from a wedge:
CPU separates blocked from busy but not USEFUL busy from useless busy, and the
scored count only moves when an EPISODE COMPLETES (15-50 min for meta4 and
black-box). The buffer is written continuously as tool calls and model responses
land. Measured on a MiniMax stream scored-static for two hours: +27 events in 60s.

NOT A RECOVERY PATH. The buffer holds only IN-FLIGHT samples; completed ones are
flushed to the .eval and dropped. The buffer for the run that lost 288 episodes
is 37.6 MB and holds 9 samples. A .db whose size matches what you lost is not
recoverable work.
"""
from __future__ import annotations

import glob
import os
import sqlite3
import sys

# Both layouts, because this file gets read by the Windows peer too. Note the
# DOUBLED component on Windows: .../inspect_ai/inspect_ai/samplebuffer.
_ROOTS = [
    os.path.expanduser("~/.local/share/inspect_ai/samplebuffer"),
    os.path.expandvars(r"%LOCALAPPDATA%\inspect_ai\inspect_ai\samplebuffer"),
    os.path.expanduser("~/AppData/Local/inspect_ai/inspect_ai/samplebuffer"),
]
TABLE = os.environ.get("SR_BUFFER_TABLE", "events")


def main() -> None:
    logdir = sys.argv[1]
    evals = glob.glob(f"logs_es/{logdir}/*.eval")
    if not evals:
        print("none")
        return
    stem = os.path.basename(max(evals, key=os.path.getmtime))

    dbs: list[str] = []
    for root in _ROOTS:
        if os.path.isdir(root):
            dbs += glob.glob(os.path.join(root, "*", f"{stem}.*.db"))
    if not dbs:
        print("none")
        return

    total = 0
    read_any = False
    for db in dbs:
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            total += con.execute(f"select count(*) from {TABLE}").fetchone()[0]
            con.close()
            read_any = True
        except Exception:
            continue
    print(total if read_any else "err")


if __name__ == "__main__":
    main()
