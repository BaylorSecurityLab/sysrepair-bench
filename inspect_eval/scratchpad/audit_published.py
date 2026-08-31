"""Recompute every published cell of tab:results-full, reporting PER SOURCE.

Three failure modes have to be told apart, and a single pooled number hides all
three:
  * wrong estimator/convention   -> value differs
  * inflated metric              -> pooling two servings ABSORBS successes, so the
                                    pooled value escapes the range of its arms
  * changed data                 -> published value is not on its population's
                                    grid, i.e. not k/n for integer k, which no
                                    estimator can produce

So this never pools. It groups by (model string, source dir) and prints each
source separately, then flags when a cell has more than one source. Grouping only
by model string would silently merge the ACSAC scaffold-study ccdc runs into the
main 9B ccdc cell, which is the same defect being audited.
"""
from collections import defaultdict
from pathlib import Path
import sysrepair_bench  # noqa: F401
from inspect_ai.log import list_eval_logs, read_eval_log
from sysrepair_bench.passk import (_attempt_outcomes, _prefix_pass_at, _mean,
                                   _is_not_applicable_sample)

EXPECT = {"meta2":40,"vulnhub":30,"ccdc":50,"ubuntu":19,"meta4":113}
COL    = {"meta2":"meta2","vulnhub":"vulnhub","ccdc":"ccdc","ubuntu":"meta3-ub","meta4":"sr-modern"}
ROOTS  = ["logs_es","logs","logs_backup","scratchpad/pro_402_archive"]
PUB = {
 "deepseek-v4-flash":{"meta2":(99.5,71.5),"vulnhub":(93.3,84.4),"ccdc":(97.3,67.3),"ubuntu":(100,52.6),"meta4":(92.8,80.4)},
 "deepseek-v4-pro":  {"meta2":(98.4,57.8)},
 "MiniMax-M3":       {"meta2":(94.8,55.3),"vulnhub":(92.2,None),"ccdc":(94.0,None),"ubuntu":(98.2,None),"meta4":(85.8,None)},
 "Qwen3.5-4B":       {"meta2":(82.5,29.3),"vulnhub":(80.5,31.0),"ccdc":(85.3,26),"ubuntu":(66.7,17),"meta4":(63.1,22)},
 "9B":               {"meta2":(83,33),"vulnhub":(85.6,40.0),"ccdc":(88.0,38.0),"ubuntu":(78.9,12.3),"meta4":(67.6,26.3)},
 "27B":              {"meta2":(97,37.5),"vulnhub":(90.0,54.4),"ccdc":(90.0,42.0),"ubuntu":(77.2,21.1),"meta4":(74.5,47.8)},
}
WANT = ("flash","pro","M3","4B","9B","27B")

src = defaultdict(dict)   # (model,mode,bench,srcdir) -> {(scen,epoch): outcomes}
seen=set()
for root in ROOTS:
    p=Path(root)
    if not p.exists(): continue
    for d in [p]+[x for x in p.rglob("*") if x.is_dir()]:
        if d.name=="smoke": continue
        try: logs=list_eval_logs(str(d))
        except Exception: continue
        for i in logs:
            b=Path(str(i.name)).name
            if b in seen: continue
            h=read_eval_log(i.name, header_only=True)
            ta=h.eval.task_args or {}
            if ta.get("solver")!="react": continue
            m=str(h.eval.model).split("/")[-1]
            if not any(w.lower() in m.lower() for w in WANT): continue
            seen.add(b)
            log=read_eval_log(i.name, header_only=False)
            mode=ta.get("mode","day1")
            for s in log.samples or []:
                meta=s.metadata or {}
                if _is_not_applicable_sample(s): continue
                o=_attempt_outcomes(s)
                if not o: continue
                src[(m,mode,meta.get("benchmark"),d.name)][(meta.get("scenario_id") or str(s.id), getattr(s,"epoch",None))]=o
print(f"loaded {len(seen)} log files, {len(src)} (model,mode,suite,source) groups\n")

def stat(d):
    v=[_prefix_pass_at(o,5,"fail") for o in d.values()]; v=[x for x in v if x is not None]
    return (100*_mean(v) if v else 0.0, len(v), len({k[0] for k in d}))

print(f"{'row':<16}{'suite':<10}{'cond':<6}{'pub':>6}  sources (each computed separately)")
issues=[]
for row,cells in PUB.items():
    for bench,(ri,bb) in cells.items():
        for cond,pub in (("day1",ri),("zero_day",bb)):
            if pub is None: continue
            groups={k:v for k,v in src.items()
                    if k[1]==cond and k[2]==bench and row.lower() in k[0].lower()}
            if not groups:
                print(f"{row:<16}{COL[bench]:<10}{cond[:4]:<6}{pub:>6}  NO DATA"); issues.append((row,bench,cond,"absent")); continue
            need=EXPECT[bench]; parts=[]; best=None
            for k,v in sorted(groups.items()):
                pct,n,scen=stat(v)
                parts.append(f"{k[0]}@{k[3][:26]}={pct:.2f}%(n={n},s={scen})")
                if best is None or scen>best[2]: best=(pct,n,scen)
            pct,n,scen=best
            kk=pub*n/100.0; ongrid=abs(kk-round(kk))<0.05
            ok=abs(pct-pub)<0.6 and scen>=need
            note="reproduces" if ok else ("INCOMPLETE" if scen<need else "MISMATCH")
            if not ongrid and scen>=need: note+=f" OFF-GRID(k={kk:.2f}/{n})"
            if len(groups)>1: note+=f" MULTI-SOURCE({len(groups)})"
            print(f"{row:<16}{COL[bench]:<10}{cond[:4]:<6}{pub:>6}  {note}")
            for pp in parts: print(f"{'':<38}{pp}")
            if not ok or not ongrid or len(groups)>1: issues.append((row,bench,cond,note))
print(f"\n{len(issues)} cells need attention")
