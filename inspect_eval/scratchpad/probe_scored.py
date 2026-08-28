#!/usr/bin/env python3
"""Deduped scored-episode count for one eval_set log dir. Prints "<status> <n>".

Uses read_eval_log_sample_summaries, NOT read_eval_log(header_only=False). The
full-sample read costs ~73s on a 32MB cell and grows with the logs, so a
five-stream supervisor tick would exceed its 300s interval and silently fall
behind exactly as the runs got interesting. Summaries carry id/epoch/scores and
return in ~0.1s, a ~300x speedup.

Two invariants this exists to preserve:

  * Count SCORED SAMPLES, never file size. A wedged run's .eval keeps growing
    with journal entries while zero samples score, so a size-based progress term
    reads healthy during precisely the failure it is meant to catch. Size is a
    liveness proxy; it cannot carry progress.

  * Read ALL .eval files in the dir and dedupe on (id, epoch). eval_set writes a
    fresh file per resume, so a newest-only read reports 0 immediately after any
    relaunch and then stays 0, making a "scored static" term permanently true.
"""
from __future__ import annotations

import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sysrepair_bench  # noqa: F401  (registers the custom sandbox provider)
from inspect_ai.log import read_eval_log, read_eval_log_sample_summaries  # noqa: E402


def main() -> None:
    logdir = sys.argv[1]
    files = glob.glob(f"logs_es/{logdir}/*.eval")
    if not files:
        print("none 0")
        return

    episodes: set[tuple] = set()
    for f in sorted(files):
        try:
            summaries = read_eval_log_sample_summaries(f)
        except Exception:
            continue
        for s in summaries:
            if getattr(s, "scores", None):
                episodes.add((str(getattr(s, "id", "")), getattr(s, "epoch", None)))

    try:
        status = read_eval_log(
            max(files, key=os.path.getmtime), header_only=True
        ).status
    except Exception:
        status = "unknown"
    print(f"{status} {len(episodes)}")


if __name__ == "__main__":
    main()
