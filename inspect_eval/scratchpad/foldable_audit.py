"""Which grid cells ALREADY have complete data but are still blank in the paper?

Zero compute: this only reads what is on disk. A cell is foldable when every
scenario of the suite has reached epochs=3. Deduped keep-last by BASENAME, since
the same run is copied under both log roots and the root prefix would otherwise
dominate the sort.
"""
from collections import defaultdict
from pathlib import Path
import sysrepair_bench  # noqa: F401
from inspect_ai.log import list_eval_logs, read_eval_log, read_eval_log_sample_summaries
from sysrepair_bench.passk import _collect, _mean

EXPECT = {"meta2": 40, "vulnhub": 30, "ccdc": 50, "ubuntu": 19, "meta4": 113}
ep = defaultdict(lambda: defaultdict(set)); src = {}
seen = set()
for root in ("logs_es", "logs"):
    p = Path(root)
    if not p.exists(): continue
    for d in [p] + [x for x in p.iterdir() if x.is_dir()]:
        if d.name == "smoke": continue
        try: logs = list_eval_logs(str(d))
        except Exception: continue
        for i in logs:
            base = Path(str(i.name)).name
            if base in seen: continue
            seen.add(base)
            h = read_eval_log(i.name, header_only=True)
            ta = h.eval.task_args or {}
            if ta.get("solver") != "react": continue
            model = str(h.eval.model).split("/")[-1]; mode = ta.get("mode", "day1")
            for s in read_eval_log_sample_summaries(i.name):
                if not (s.scores or {}): continue
                b = (s.metadata or {}).get("benchmark")
                ep[(model, mode)][b].add((str(s.id), s.epoch))

print(f"{'model':<20}{'mode':<10}{'suite':<10}{'scen@E3':>9}{'need':>6}   state")
rows = []
for (model, mode) in sorted(ep):
    for b, pairs in sorted(ep[(model, mode)].items(), key=lambda x: str(x[0])):
        by = defaultdict(set)
        for sid, e in pairs: by[sid].add(e)
        full = sum(1 for v in by.values() if len(v) >= 3)
        need = EXPECT.get(b)
        if need is None: continue
        state = "COMPLETE" if full >= need else f"partial ({len(by)} seen)"
        print(f"{model:<20}{mode:<10}{str(b):<10}{full:>9}{need:>6}   {state}")
        if full >= need: rows.append((model, mode, b))
print(f"\n{len(rows)} complete model/suite/condition cells on disk")
