"""Suite-wide N/A-regression audit using SAMPLE SUMMARIES (no full log reads).

Summaries carry security_pass/regression_pass in score metadata and `benchmark`
in sample metadata, so the whole corpus can be audited in seconds. Answers one
question: does ANY dir contain an N/A-regression episode on a given suite? The
claim "meta2 has none" is what lets the meta2 CDR figure ship unchanged, so it
has to hold across every dir, not the two it was first measured on.
"""
import sys
from collections import defaultdict
from pathlib import Path
import sysrepair_bench  # noqa: F401
from inspect_ai.log import list_eval_logs, read_eval_log_sample_summaries

want = sys.argv[1] if len(sys.argv) > 1 else None
tot = defaultdict(int); na = defaultdict(int); na_pass = defaultdict(int)
per_dir_na = defaultdict(int)
seen = {}
dirs = sorted(p for p in Path("logs_es").iterdir() if p.is_dir())
for d in dirs:
    try:
        logs = list_eval_logs(str(d))
    except Exception as e:
        print(f"!! {d.name}: {e}"); continue
    for i in logs:
        try:
            summaries = read_eval_log_sample_summaries(i.name)
        except Exception:
            continue
        for s in summaries:
            b = (s.metadata or {}).get("benchmark")
            if want and b != want:
                continue
            sc = s.scores or {}
            if not sc:
                continue
            v = list(sc.values())[-1]
            md = getattr(v, "metadata", None) or {}
            if "security_pass" not in md:
                continue
            k = (d.name, b, str(s.id), s.epoch)
            if k in seen and str(i.name) < seen[k]:
                continue
            seen[k] = str(i.name)
            tot[b] += 1
            if md.get("regression_pass") is None:
                na[b] += 1
                per_dir_na[(d.name, b)] += 1
                if md.get("security_pass"):
                    na_pass[b] += 1

print(f"=== N/A-regression audit across {len(dirs)} dirs" + (f" [suite={want}]" if want else "") + " ===")
for b in sorted(tot, key=str):
    flag = "" if na[b] == 0 else "   <-- N/A PRESENT"
    print(f"{str(b):<16} episodes={tot[b]:<6} N/A={na[b]:<5} of those passed security={na_pass[b]:<5}{flag}")
if per_dir_na:
    print("\nDirs contributing N/A episodes:")
    for (dn, b), c in sorted(per_dir_na.items(), key=lambda x: -x[1]):
        print(f"   {dn:<46} {str(b):<12} {c}")
