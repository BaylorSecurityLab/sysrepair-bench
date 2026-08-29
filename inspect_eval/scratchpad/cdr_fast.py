"""CDR from SAMPLE SUMMARIES, replicating cdr.py exactly at a fraction of the cost.

Same rules as cdr.py: skip not-applicable samples, require security_pass, EXCLUDE
regression_pass is None, dedupe on (model, mode, benchmark, scenario, epoch)
keep-last by log path. Prints the excluded count so the denominator is visible.

Usage: cdr_fast.py <suite> <dir> [dir ...]
"""
import sys
from collections import defaultdict
from pathlib import Path
import sysrepair_bench  # noqa: F401
from inspect_ai.log import list_eval_logs, read_eval_log_sample_summaries, read_eval_log

suite = sys.argv[1]
for d in sys.argv[2:]:
    episodes, na = {}, set()
    for i in list_eval_logs(d):
        h = read_eval_log(i.name, header_only=True)
        model = (h.eval.model or "?").split("/")[-1]
        mode = (h.eval.task_args or {}).get("mode", "day1")
        for s in read_eval_log_sample_summaries(i.name):
            if (s.metadata or {}).get("benchmark") != suite:
                continue
            sc = s.scores or {}
            if not sc:
                continue
            v = list(sc.values())[-1]
            md = getattr(v, "metadata", None) or {}
            if md.get("not_applicable") is True or getattr(v, "value", None) == "N":
                continue
            if "security_pass" not in md:
                continue
            key = (model, mode, str(s.id), s.epoch)
            if md.get("regression_pass") is None:
                na.add(key); continue
            prev = episodes.get(key)
            if prev is None or str(i.name) >= prev[0]:
                episodes[key] = (str(i.name), bool(md["security_pass"]),
                                 bool(md["security_pass"]) and bool(md["regression_pass"]))
    cell = defaultdict(lambda: [0, 0, 0])
    for (m, mo, _s, _e), (_p, sec, joint) in episodes.items():
        c = cell[(m, mo)]; c[0] += sec; c[1] += joint; c[2] += 1
    for k in sorted(cell):
        sec, joint, n = cell[k]
        cdr = 0.0 if sec == 0 else 100*(sec-joint)/sec
        nak = sum(1 for x in na if (x[0], x[1]) == k)
        print(f"{Path(d).name:<40} {suite:<9} {k[0]:<16}{k[1]:<10} "
              f"sec={100*sec/n:5.1f}% joint={100*joint/n:5.1f}% CDR={cdr:5.1f}% (n={n})"
              + (f"  [{nak} excluded]" if nak else ""))
