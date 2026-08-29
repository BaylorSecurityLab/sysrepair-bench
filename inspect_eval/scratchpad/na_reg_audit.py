"""Count N/A-regression episodes per (dir, benchmark) and how many passed security.

Metadata-absence coincides with failure on some tracks and not on others, so
COUNT WHICH WAY IT RUNS before excluding on any predicate. Measured here: on
vulnhub most excluded episodes PASSED security (118 of 158 raw records), on meta4
almost none did (2 of 55). Same predicate, opposite sign, same corpus.

Note cdr.py drops an episode at three separate points, and only the third is the
N/A-regression exclusion this script measures:
  A  _is_not_applicable_sample  -- scenario deliberately skipped. Never fires on
     our corpus: 0 of 11504 records.
  B  "security_pass" not in md  -- no two-component metadata at all. 365 records,
     of which 2 passed, so this one IS confounded with failure. CDR is
     ALGEBRAICALLY INVARIANT to B: (sec-joint)/sec counts only security-passing
     episodes and these have no security_pass, so B moves only the per-n
     sec/joint percentages, which the paper does not use.
  C  regression_pass is None    -- scenario defines no regression check. This is
     the exclusion, and the one this script counts.
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
