"""Re-derive EVERY day1/zero_day cost pair, self-checking, across all log roots.

Keys per FILE, not per directory: logs/ is a flat directory mixing many
model/solver/mode combinations, so taking one header per directory
mis-assigns samples. Suite and model come from the DATA, never the dir name.

Rules fixed once: scored-only (scores present, no error), deduped keep-last by
log BASENAME, working_time not total_time, median not mean, at-cap at 0.95*limit.
A pair is (model, solver, suite) with both arms present.

Keep-last compares the BASENAME, not the full path. Filenames are ISO timestamps,
so the basename orders chronologically; the full path does not, because the root
prefix dominates it. Comparing full paths across two roots picks by directory
rather than by recency: "logs/2026-08-27..." sorts BEFORE "logs_es/2026-08-20..."
because "/" (0x2F) precedes "_" (0x5F), so the older run wins. That silently
selected a stale Qwen3.5-27B meta2 zero_day run whose median was 204s over the
current one at 2408s, turning a 5.06x pair into a spurious 0.43x. The same file
also appears under both roots, so identical basenames are skipped outright.
"""
import statistics as st, sys
from collections import defaultdict
from pathlib import Path
import sysrepair_bench  # noqa: F401
from inspect_ai.log import list_eval_logs, read_eval_log, read_eval_log_sample_summaries

ROOTS = sys.argv[1:] or ["logs_es", "logs"]
arms = defaultdict(lambda: defaultdict(dict))   # (model,solver,mode) -> suite -> {(id,epoch): (w, path)}
caps = {}
files = []
for root in ROOTS:
    p = Path(root)
    if not p.exists(): continue
    cand = [p] + [x for x in p.iterdir() if x.is_dir()]
    for d in cand:
        if d.name == "smoke": continue
        try: files += sorted(list_eval_logs(str(d)), key=lambda x: str(x.name))
        except Exception: pass

seen_names = set()
for i in files:
    base = Path(str(i.name)).name
    if base in seen_names: continue
    seen_names.add(base)
    h = read_eval_log(i.name, header_only=True)
    ta = h.eval.task_args or {}
    key = (str(h.eval.model).split("/")[-1], ta.get("solver", "?"), ta.get("mode", "day1"))
    caps[key] = getattr(h.eval.config, "working_limit", None)
    for s in read_eval_log_sample_summaries(i.name):
        if getattr(s, "error", None) or not (s.scores or {}): continue
        suite = (s.metadata or {}).get("benchmark")
        slot = arms[key][suite]
        k = (str(s.id), s.epoch)
        if k in slot and base < slot[k][1]: continue
        slot[k] = (getattr(s, "working_time", None) or 0.0, base)

print(f"{'model':<20}{'solver':<16}{'suite':<10}{'n_d1':>6}{'med_d1':>8}"
      f"{'n_zd':>6}{'med_zd':>8}{'ratio':>8}{'capd':>6}")
pairs = []
for model, solver in sorted({(m, s) for (m, s, _) in arms}):
    d1 = arms.get((model, solver, "day1"), {})
    zd = arms.get((model, solver, "zero_day"), {})
    wl = caps.get((model, solver, "zero_day"))
    for suite in sorted(set(d1) & set(zd), key=str):
        a = [w for w, _ in d1[suite].values()]; b = [w for w, _ in zd[suite].values()]
        if not a or not b: continue
        ma, mb = st.median(a), st.median(b)
        atcap = sum(1 for x in b if wl and x >= 0.95*wl)
        censored = bool(wl and mb >= wl - 8)
        pairs.append((model, solver, suite, mb/ma if ma else float("nan"), censored, len(a), len(b)))
        print(f"{model:<20}{solver:<16}{str(suite):<10}{len(a):>6}{ma:>8.0f}"
              f"{len(b):>6}{mb:>8.0f}{mb/ma:>8.2f}{'  CENS' if censored else '':>6}")

def sm(sel, label):
    rs = sorted(p[3] for p in sel)
    if not rs: print(f"{label}: none"); return
    print(f"{label}: n={len(rs)} median={st.median(rs):.2f}x range={rs[0]:.2f}-{rs[-1]:.2f}x")

print(f"\ntotal pairs = {len(pairs)}")
nh = [p for p in pairs if p[2] != "hivestorm"]
unc = [p for p in nh if not p[4]]
sm(pairs, "ALL")
sm(nh, "excl hivestorm")
sm(unc, "excl hivestorm + censored")
sm([p for p in unc if p[1] == "react"], "react only, excl hivestorm + censored")
sm([p for p in unc if p[1] == "react" and p[0] != "MiniMax-M2.7"],
   "react, excl hivestorm + censored + M2.7 (ICLR scope)")
print("censored: " + ", ".join(f"{p[0]}/{p[1]}/{p[2]}" for p in nh if p[4]))
