"""Compute EVERY published cell under ONE convention, so the decision is yes/no.

Convention (already used by fold_cell.py, which reproduces the 9B row exactly):
pool all log roots, dedup keep-last by log BASENAME so the newest run supersedes
an earlier partial for the same (scenario, epoch), then pass@5 via
_prefix_pass_at with unresolved="fail".

This is deliberately NOT the audit's per-source view. The audit's job was to
expose that sources disagree; this one's job is to say what each cell IS under a
single stated rule. Asking a human to pick a source per cell for 38 cells is not
a reasonable decision to hand over; picking one rule is.
"""
from collections import defaultdict
from pathlib import Path
import sysrepair_bench  # noqa: F401
from inspect_ai.log import list_eval_logs, read_eval_log
from sysrepair_bench.passk import (_attempt_outcomes, _prefix_pass_at, _mean,
                                   _is_not_applicable_sample)

EXPECT={"meta2":40,"vulnhub":30,"ccdc":50,"ubuntu":19,"meta4":113}
COL={"meta2":"meta2","vulnhub":"vulnhub","ccdc":"ccdc","ubuntu":"meta3-ub","meta4":"sr-modern"}
ROOTS=["logs_es","logs","logs_backup","scratchpad/pro_402_archive"]
PUB={
 "deepseek-v4-flash":{"meta2":(99.5,71.5),"vulnhub":(93.3,84.4),"ccdc":(97.3,67.3),"ubuntu":(100,52.6),"meta4":(92.8,80.4)},
 "deepseek-v4-pro":  {"meta2":(98.4,57.8)},
 "MiniMax-M3":       {"meta2":(94.8,55.3),"vulnhub":(92.2,None),"ccdc":(94.0,None),"ubuntu":(98.2,None),"meta4":(85.8,None)},
 "Qwen3.5-4B":       {"meta2":(82.5,29.3),"vulnhub":(80.5,31.0),"ccdc":(85.3,26),"ubuntu":(66.7,17),"meta4":(63.1,22)},
 "9b":               {"meta2":(83,33),"vulnhub":(85.6,40.0),"ccdc":(88.0,38.0),"ubuntu":(78.9,12.3),"meta4":(67.6,26.3)},
 "27b":              {"meta2":(97,37.5),"vulnhub":(90.0,54.4),"ccdc":(90.0,42.0),"ubuntu":(77.2,21.1),"meta4":(74.5,47.8)},
}
WANT=("flash","pro","m3","4b","9b","27b")

ep={}; src={}; seen=set()
for root in ROOTS:
    p=Path(root)
    if not p.exists(): continue
    for d in [p]+[x for x in p.rglob("*") if x.is_dir()]:
        if d.name=="smoke": continue
        try: logs=list_eval_logs(str(d))
        except Exception: continue
        for i in logs:
            base=Path(str(i.name)).name
            if base in seen: continue
            h=read_eval_log(i.name, header_only=True)
            ta=h.eval.task_args or {}
            if ta.get("solver")!="react": continue
            m=str(h.eval.model).split("/")[-1]
            if not any(w in m.lower() for w in WANT): continue
            seen.add(base)
            log=read_eval_log(i.name, header_only=False)
            mode=ta.get("mode","day1")
            for s in log.samples or []:
                meta=s.metadata or {}
                if _is_not_applicable_sample(s): continue
                o=_attempt_outcomes(s)
                if not o: continue
                k=(m.lower(),mode,meta.get("benchmark"),meta.get("scenario_id") or str(s.id),getattr(s,"epoch",None))
                if k in src and base < src[k]: continue     # keep-last by BASENAME
                src[k]=base; ep[k]=o
print(f"loaded {len(seen)} files, {len(ep)} deduped episodes\n")
print(f"{'row':<18}{'suite':<11}{'cond':<6}{'published':>10}{'canonical':>11}{'delta':>8}  scen  status")
for row,cells in PUB.items():
    for b,(ri,bb) in cells.items():
        for cond,pub in (("day1",ri),("zero_day",bb)):
            if pub is None: continue
            d={k:v for k,v in ep.items() if k[1]==cond and k[2]==b and row.lower() in k[0]}
            if not d:
                print(f"{row:<18}{COL[b]:<11}{cond[:4]:<6}{pub:>10}{'ABSENT':>11}"); continue
            scen=len({k[3] for k in d})
            v=[_prefix_pass_at(o,5,"fail") for o in d.values()]; v=[x for x in v if x is not None]
            got=100*_mean(v)
            need=EXPECT[b]
            st = "OK" if abs(got-pub)<0.6 else "CHANGES"
            if scen<need: st += f" (partial {scen}/{need})"
            print(f"{row:<18}{COL[b]:<11}{cond[:4]:<6}{pub:>10}{got:>10.2f}%{got-pub:>+8.2f}  {scen:>3}  {st}")
