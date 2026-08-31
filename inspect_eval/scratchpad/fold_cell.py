"""Compute the foldable pass@5 cells for one model+mode, ready for tab:results-full.

Refuses to emit a number for any suite that is not COMPLETE (every scenario at
epochs>=3), because a partial cell folded as if complete is indistinguishable in
the table from a real one.

Uses passk's own estimator (_attempt_outcomes + _prefix_pass_at with the "fail"
policy, which counts budget-exhausted episodes as failures). An ad-hoc "any
epoch passed" calculation OVERESTIMATES badly: on the ladder rungs it gave 25.9%
where the real value was 11.1%.

Reads every log root, deduped keep-last by BASENAME -- the root prefix would
otherwise dominate the sort and let a stale run win.

    python3 scratchpad/fold_cell.py <model-substring> <day1|zero_day>
"""
import sys
from collections import defaultdict
from pathlib import Path
import sysrepair_bench  # noqa: F401
from inspect_ai.log import list_eval_logs, read_eval_log
from sysrepair_bench.passk import (_attempt_outcomes, _prefix_pass_at, _mean,
                                   _is_not_applicable_sample)

EXPECT = {"meta2": 40, "vulnhub": 30, "ccdc": 50, "ubuntu": 19, "meta4": 113}
COL = {"meta2": "meta2", "vulnhub": "vulnhub", "ccdc": "ccdc",
       "ubuntu": "meta3-ub", "meta4": "sr-modern"}
ROOTS = ["logs_es", "logs", "logs_backup", "scratchpad/pro_402_archive"]

def main(model_sub, mode):
    episodes, seen = {}, set()
    for root in ROOTS:
        p = Path(root)
        if not p.exists(): continue
        for d in [p] + [x for x in p.rglob("*") if x.is_dir()]:
            if d.name == "smoke": continue
            try: logs = list_eval_logs(str(d))
            except Exception: continue
            for i in logs:
                base = Path(str(i.name)).name
                if base in seen: continue
                h = read_eval_log(i.name, header_only=True)
                ta = h.eval.task_args or {}
                if model_sub not in str(h.eval.model): continue
                if ta.get("solver") != "react" or ta.get("mode") != mode: continue
                seen.add(base)
                log = read_eval_log(i.name, header_only=False)
                for s in log.samples or []:
                    meta = s.metadata or {}
                    if _is_not_applicable_sample(s): continue
                    o = _attempt_outcomes(s)
                    if not o: continue
                    key = (meta.get("benchmark"),
                           meta.get("scenario_id") or str(s.id),
                           getattr(s, "epoch", None))
                    episodes[key] = o

    per = defaultdict(dict)
    for (b, sid, ep), o in episodes.items():
        per[b].setdefault(sid, {})[ep] = o

    print(f"{model_sub}  {mode}   ({len(seen)} log files)")
    ready = {}
    for b in sorted(per, key=str):
        need = EXPECT.get(b)
        if need is None: continue
        full = sum(1 for v in per[b].values() if len(v) >= 3)
        vals = [_prefix_pass_at(o, 5, "fail")
                for sc in per[b].values() for o in sc.values()]
        vals = [v for v in vals if v is not None]
        pct = 100 * _mean(vals) if vals else 0.0
        if full >= need:
            ready[b] = pct
            print(f"  {COL.get(b,b):<11} COMPLETE  {full}/{need} scen   "
                  f"pass@5 = {pct:5.2f}%   n={len(vals)}")
        else:
            print(f"  {COL.get(b,b):<11} partial   {full}/{need} scen   "
                  f"(would be {pct:5.2f}%, DO NOT FOLD)")
    if ready:
        print("\n  foldable now: " + ", ".join(f"{COL.get(b,b)}={v:.1f}" for b, v in sorted(ready.items())))
    else:
        print("\n  nothing foldable yet")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
