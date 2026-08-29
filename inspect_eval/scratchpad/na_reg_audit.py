"""Count N/A-regression episodes per (dir, benchmark) and how many passed security.

The exclusion is correct for CDR and dangerous for accuracy. A peer measured a
track where EVERY N/A-regression episode was a failure, so excluding them lifted
an accuracy cell from 90.5% to 100.0%. This prints the direction of that
confound on our own cells so it is never assumed.
"""
import sys
from collections import defaultdict
from pathlib import Path
import sysrepair_bench  # noqa: F401
from inspect_ai.log import list_eval_logs, read_eval_log
from sysrepair_bench.passk import _final_score, _is_not_applicable_sample

for d in sys.argv[1:]:
    tot = defaultdict(int); na = defaultdict(int); na_pass = defaultdict(int)
    seen = {}
    for i in list_eval_logs(d):
        log = read_eval_log(i.name, header_only=False)
        for s in log.samples or []:
            if _is_not_applicable_sample(s):
                continue
            sc = _final_score(s)
            if sc is None:
                continue
            md = sc.metadata or {}
            if "security_pass" not in md:
                continue
            b = (s.metadata or {}).get("benchmark")
            k = (b, str(s.id), s.epoch)
            if k in seen and str(i.name) < seen[k]:
                continue
            seen[k] = str(i.name)
            tot[b] += 1
            if md.get("regression_pass") is None:
                na[b] += 1
                if md.get("security_pass"):
                    na_pass[b] += 1
    print(f"{Path(d).name}")
    for b in sorted(tot, key=lambda x: str(x)):
        if na[b]:
            print(f"   {str(b):<14} N/A {na[b]:>3} of {tot[b]:>4}   of those PASSED security: {na_pass[b]:>3}")
    if not any(na.values()):
        print("   no N/A-regression episodes (fix is a no-op here)")
