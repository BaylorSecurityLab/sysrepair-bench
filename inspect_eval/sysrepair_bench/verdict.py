"""The single definition of what counts as a PASS.

WHY THIS MODULE EXISTS
Three modules in this package each carried their own `_is_pass`, and they did not
agree:

    passk.py           ("C", "CORRECT", "1", "1.0", "TRUE")     correct
    summarize.py       ("C", "CORRECT", "1", "1.0", "TRUE")     correct
    category_table.py  ("CORRECT", "TRUE", "1", "PASS")         MISSING "C"

Our scorer emits inspect's `CORRECT` constant, which serialises as the single
character **"C"**. Measured on the Qwen3.5-27B day1 logs: 495 scores of "C" and
121 of "I", and nothing else. So category_table graded EVERY passing episode as a
failure and would print 0.0% for every category of a suite passing at ~80%. The
peer measured the same on a 90.5% cell: four categories, all 0.0%.

Nothing wrong reached the paper (there is no category table in it, and the CDR
figures come from cdr.py, which reads the security_pass/regression_pass BOOLEANS
from metadata and never touches the score string). But category_table has a
`--latex --out app_categories.tex` mode written to generate an appendix table, so
the trap was armed and pointed at the paper.

THE STRUCTURAL POINT, which is the reason this file exists rather than a
three-line patch: the shared assumption was not "dedup", it was "what counts as a
pass", and that one is more dangerous precisely because it was DUPLICATED rather
than centralised. Three copies can drift; one imported definition cannot. When a
defect turns up, the question is which siblings share the assumption.
"""

from __future__ import annotations

from typing import Any

# "C"/"I" are how inspect's CORRECT/INCORRECT serialise in a .eval. The long
# spellings and numerics are accepted because older logs and hand-built fixtures
# use them.
PASS_VALUES = ("C", "CORRECT", "1", "1.0", "TRUE", "PASS")


def is_pass(value: Any) -> bool:
    """True if this score value denotes a pass. The ONLY definition; import it."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value > 0
    return str(value).strip().upper() in PASS_VALUES
