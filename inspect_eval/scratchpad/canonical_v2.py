"""Canonical cell values, STATUS-AWARE, with a cached parse.

Why status matters: the corpus is majority-incomplete. Across all react logs
there are 45 'started', 20 'error' and 6 'cancelled' against only 52 'success'.
A keep-last rule that ignores status lets an interrupted partial supersede a
completed run purely by being newer. That is what makes the 4B vulnhub black-box
cell unmeasurable: three interrupted runs at 1 epoch/scenario, two of which
disagree by 31 points (28.57 vs 60.00).

Rule: prefer episodes from status=success logs. Fall back to a partial only when
no successful log covers that (scenario, epoch), and report how many episodes
came from each tier so a cell resting on partials is visible rather than silent.
Within a tier, keep-last by BASENAME (filenames are ISO timestamps; full paths
sort by root prefix instead).

The parse is cached to scratchpad/.episode_cache.json.gz so later analyses are
seconds rather than the ~50 minutes a full read costs.
"""
import gzip, json, sys
from collections import defaultdict
from pathlib import Path
import sysrepair_bench  # noqa: F401
from inspect_ai.log import list_eval_logs, read_eval_log
from sysrepair_bench.passk import (_attempt_outcomes, _prefix_pass_at, _mean,
                                   _is_not_applicable_sample)

CACHE = Path("scratchpad/.episode_cache.json.gz")
ROOTS = ["logs_es","logs","logs_backup","scratchpad/pro_402_archive"]
TIER  = {"success":0, "cancelled":1, "started":2, "error":3}   # lower is better

def build():
    recs=[]; seen=set()
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
                seen.add(base)
                log=read_eval_log(i.name, header_only=False)
                for s in log.samples or []:
                    meta=s.metadata or {}
                    if _is_not_applicable_sample(s): continue
                    o=_attempt_outcomes(s)
                    if not o: continue
                    recs.append([str(h.eval.model).split("/")[-1], ta.get("mode","day1"),
                                 meta.get("benchmark"), meta.get("scenario_id") or str(s.id),
                                 getattr(s,"epoch",None), h.status, base, o])
    with gzip.open(CACHE,"wt") as f: json.dump(recs,f)
    return recs

recs = json.load(gzip.open(CACHE,"rt")) if CACHE.exists() and "--rebuild" not in sys.argv else build()
print(f"{len(recs)} episode records cached at {CACHE}\n")

best={}
for model,mode,bench,sid,epoch,status,base,o in recs:
    k=(model.lower(),mode,bench,sid,epoch)
    cand=(TIER.get(status,9), base)
    if k in best and (best[k][0], best[k][1]) <= cand: continue
    best[k]=(cand[0],cand[1],o,status)

EXPECT={"meta2":40,"vulnhub":30,"ccdc":50,"ubuntu":19,"meta4":113}
COL={"meta2":"meta2","vulnhub":"vulnhub","ccdc":"ccdc","ubuntu":"meta3-ub","meta4":"sr-modern"}
PUB={"deepseek-v4-flash":{"meta2":(99.5,71.5),"vulnhub":(93.3,84.4),"ccdc":(97.3,67.3),"ubuntu":(100,52.6),"meta4":(92.8,80.4)},
 "deepseek-v4-pro":{"meta2":(98.4,57.8)},
 "minimax-m3":{"meta2":(94.8,55.3),"vulnhub":(92.2,None),"ccdc":(94.0,None),"ubuntu":(98.2,None),"meta4":(85.8,None)},
 "qwen3.5-4b":{"meta2":(82.5,29.3),"vulnhub":(80.5,31.0),"ccdc":(85.3,26),"ubuntu":(66.7,17),"meta4":(63.1,22)},
 "9b":{"meta2":(83,33),"vulnhub":(85.6,40.0),"ccdc":(88.0,38.0),"ubuntu":(78.9,12.3),"meta4":(67.6,26.3)},
 "27b":{"meta2":(97,37.5),"vulnhub":(90.0,54.4),"ccdc":(90.0,42.0),"ubuntu":(77.2,21.1),"meta4":(74.5,47.8)}}

print(f"{'row':<18}{'suite':<11}{'cond':<6}{'pub':>7}{'canon':>9}{'delta':>8} scen  from-success  verdict")
for row,cells in PUB.items():
    for b,(ri,bb) in cells.items():
        for cond,pub in (("day1",ri),("zero_day",bb)):
            if pub is None: continue
            d={k:v for k,v in best.items() if k[1]==cond and k[2]==b and row in k[0]}
            if not d: print(f"{row:<18}{COL[b]:<11}{cond[:4]:<6}{pub:>7}   ABSENT"); continue
            scen=len({k[3] for k in d})
            vals=[_prefix_pass_at(v[2],5,"fail") for v in d.values()]
            vals=[x for x in vals if x is not None]
            got=100*_mean(vals)
            nsucc=sum(1 for v in d.values() if v[3]=="success")
            need=EXPECT[b]
            verdict = "OK" if abs(got-pub)<0.6 else "CHANGES"
            if scen<need: verdict+=f" partial {scen}/{need}"
            if nsucc < len(d): verdict+=f" RESTS-ON-PARTIALS({len(d)-nsucc}/{len(d)} eps)"
            print(f"{row:<18}{COL[b]:<11}{cond[:4]:<6}{pub:>7}{got:>8.2f}%{got-pub:>+8.2f} {scen:>4}  {nsucc:>4}/{len(d):<5}  {verdict}")
