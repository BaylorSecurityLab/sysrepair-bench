"""Per-category accuracy table for SysRepair-Bench.

Reads all .eval log files as ZIP archives (bypasses the Inspect AI
sandbox-config deserialiser, which currently raises NotImplementedError
on these logs), then groups samples by remediation category and computes
per-category success rates.

Category is determined in priority order:
  1. Explicit ``## Category`` section in the scenario's ``threat.md``
  2. Keyword analysis of the threat.md remediation section
  3. Fall-through: *Configuration Hardening*

Usage:
    uv run python -m sysrepair_bench.category_table ./logs
    uv run python -m sysrepair_bench.category_table ./logs --latex
    uv run python -m sysrepair_bench.category_table ./logs --latex --out app_categories.tex
    uv run python -m sysrepair_bench.category_table ./logs --model Qwen3.5-9B
"""

from __future__ import annotations

import json
import re
import zipfile
from collections import defaultdict
from pathlib import Path
from textwrap import dedent
from typing import Any

# ---------------------------------------------------------------------------
# Category classification
# ---------------------------------------------------------------------------

_EXPLICIT_RE = re.compile(
    r"^##\s*(?:remediation\s+)?category\s*\n(.+)",
    re.IGNORECASE | re.MULTILINE,
)
_BOLD_CATEGORY_RE = re.compile(r"\*\*Category:\*\*\s*(.+)", re.IGNORECASE)
_COMP_CTRL_HEADER_RE = re.compile(
    r"^##\s*Remediation(?:\s+Steps?)?\s*\((?:compensating control|do NOT upgrade)",
    re.IGNORECASE | re.MULTILINE,
)

CATEGORIES: dict[str, str] = {
    "compensating": "Compensating Controls",
    "network": "Network Security",
    "dependency": "Dependency & Package Management",
    "package": "Dependency & Package Management",
    "access": "Access Control",
    "configuration": "Configuration Hardening",
    "hardening": "Configuration Hardening",
}

_NETWORK_SEC_PATTERNS = ["network", "firewall", "iptables", "nftables", "tls", "ssl", "cipher", "exposed port"]
_DEP_PKG_PATTERNS = ["upgrade", "update the package", "install.*version", r"cve-\d{4}", "patch"]
_ACCESS_CTRL_PATTERNS = ["access control", "permission", "privilege", "sudo", "group membership", "authorized_keys", "authenticat"]


def _remediation_text(threat_path: Path) -> str:
    """Extract the remediation section from a threat.md; falls back to full text."""
    full_text = threat_path.read_text(encoding="utf-8", errors="ignore")
    m = re.search(
        r"^##\s*Remediation(?:\s+Steps?|\s+\(.*?\))?\s*\n(.*?)(?=\n##|\Z)",
        full_text,
        re.DOTALL | re.MULTILINE | re.IGNORECASE,
    )
    if m:
        return m.group(1)
    return full_text


def classify_threat(threat_path: Path) -> str:
    """Return the remediation category for a scenario given its threat.md path."""
    if not threat_path.exists():
        return "Configuration Hardening"

    full_text = threat_path.read_text(encoding="utf-8", errors="ignore")

    # 1. Explicit ## Category section
    m = _EXPLICIT_RE.search(full_text)
    if m:
        return m.group(1).strip().strip("*").strip()

    # 2. **Category:** bold marker
    m = _BOLD_CATEGORY_RE.search(full_text)
    if m:
        return m.group(1).strip().strip("*").strip()

    # 3. Compensating-control remediation header
    if _COMP_CTRL_HEADER_RE.search(full_text):
        return "Compensating Controls"

    # 4. Keyword analysis of remediation section
    remedy = _remediation_text(threat_path).lower()
    text_lower = full_text.lower()

    if "compensating control" in remedy:
        return "Compensating Controls"
    for pat in _NETWORK_SEC_PATTERNS:
        if re.search(pat, remedy, re.IGNORECASE):
            return "Network Security"
    for pat in _DEP_PKG_PATTERNS:
        if re.search(pat, remedy, re.IGNORECASE):
            return "Dependency & Package Management"
    for pat in _ACCESS_CTRL_PATTERNS:
        if re.search(pat, remedy, re.IGNORECASE):
            return "Access Control"

    return "Configuration Hardening"


# ---------------------------------------------------------------------------
# Log reading (ZIP-based, bypasses broken config_deserialize)
# ---------------------------------------------------------------------------

# Was a local copy that omitted "C", the exact string our scorer emits, so every
# passing episode graded as a failure and every category printed 0.0%. See
# verdict.py for the measurement and why this is now imported rather than defined.
from .verdict import is_pass as _is_pass


def _read_log_zip(log_path: Path) -> list[dict]:
    """Return a list of sample dicts from a .eval ZIP archive."""
    samples: list[dict] = []
    try:
        with zipfile.ZipFile(log_path) as z:
            for name in z.namelist():
                if not (name.startswith("samples/") and name.endswith(".json")):
                    continue
                try:
                    data = json.loads(z.read(name))
                    samples.append(data)
                except Exception:
                    continue
    except Exception:
        pass
    return samples


# ---------------------------------------------------------------------------
# __main__ — per-category accuracy report
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys
    from tabulate import tabulate

    parser = argparse.ArgumentParser(description="Per-category accuracy table")
    parser.add_argument("log_dir", nargs="?", default="./logs")
    parser.add_argument("--latex", action="store_true")
    parser.add_argument("--out", default=None)
    parser.add_argument("--model", default=None)
    args = parser.parse_args()

    log_dir = Path(args.log_dir)
    eval_files = sorted(log_dir.glob("*.eval"))
    if not eval_files:
        print(f"No .eval files found in {log_dir}", file=sys.stderr)
        sys.exit(1)

    by_category: dict[str, list[bool]] = defaultdict(list)

    for ef in eval_files:
        for sample in _read_log_zip(ef):
            model = (sample.get("eval", {}) or {}).get("model", "")
            if args.model and args.model not in model:
                continue
            meta = sample.get("metadata") or {}
            category = meta.get("category", "Configuration Hardening")
            scores = sample.get("scores") or {}
            passed = any(_is_pass(v.get("value") if isinstance(v, dict) else v)
                         for v in scores.values())
            by_category[category].append(passed)

    if not by_category:
        print("No samples found.", file=sys.stderr)
        sys.exit(1)

    rows = []
    for cat in sorted(by_category):
        results = by_category[cat]
        n = len(results)
        p = sum(results)
        rows.append([cat, n, p, f"{p / n:.1%}"])

    headers = ["Category", "N", "Pass", "Accuracy"]
    if args.latex:
        table = tabulate(rows, headers=headers, tablefmt="latex_booktabs")
    else:
        table = tabulate(rows, headers=headers, tablefmt="simple")

    if args.out:
        Path(args.out).write_text(table + "\n", encoding="utf-8")
        print(f"Written to {args.out}")
    else:
        print(table)
