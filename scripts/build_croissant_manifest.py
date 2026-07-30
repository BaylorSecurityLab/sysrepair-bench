"""Build scenarios.jsonl manifest used by croissant.json.

Walks every suite under the repo root, extracts per-scenario metadata from the
threat description and Dockerfile/Vagrantfile, and writes one JSON object per
scenario to scenarios.jsonl. Output is deterministic (sorted by scenario_id).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "scenarios.jsonl"

SUITES = {
    "meta2": {"root": "meta2", "kind": "linux-container"},
    "meta3-ubuntu": {"root": "meta3/ubuntu", "kind": "linux-container"},
    "meta3-windows": {"root": "meta3/windows", "kind": "windows-container"},
    "meta4": {"root": "meta4", "kind": "linux-container"},
    "meta4-ad-vm": {"root": "meta4/ad-vm", "kind": "windows-vm"},
    "ccdc": {"root": "ccdc", "kind": "linux-container"},
    "vulnhub": {"root": "vulnhub", "kind": "linux-container"},
    "hivestorm": {"root": "hivestorm", "kind": "mixed"},
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
CWE_RE = re.compile(r"CWE-\d{1,5}")
SEVERITY_RE = re.compile(
    r"(?:\*\*Severity[:\s]*\*\*|\*\*Severity[:\s]+|Severity[:\s]+)\s*"
    r"\*?\*?(Critical|High|Medium|Low|Informational)\*?\*?",
    re.IGNORECASE,
)
SEVERITY_BOLD_RE = re.compile(
    r"\*\*(Critical|High|Medium|Low|Informational)\*\*", re.IGNORECASE
)
CVSS_RE = re.compile(r"CVSS\s*([0-9]+\.[0-9]+)", re.IGNORECASE)
TITLE_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


def find_threat_doc(scenario_dir: Path) -> Path | None:
    for name in ("threat.md", "task.md.tmpl", "README.md"):
        candidate = scenario_dir / name
        if candidate.is_file():
            return candidate
    return None


def detect_lab_os(scenario_dir: Path) -> str | None:
    """Return the guest OS of an AutomatedLab/Hyper-V scenario, else None.

    ``lab/automatedlab.json`` is the marker a scenario is provisioned by
    AutomatedLab on Hyper-V rather than Vagrant/VirtualBox; its ``os`` field
    names the guest ("windows", "freebsd", "linux").
    """
    manifest = scenario_dir / "lab" / "automatedlab.json"
    if not manifest.is_file():
        return None
    try:
        return json.loads(manifest.read_text(encoding="utf-8")).get("os") or None
    except (json.JSONDecodeError, OSError):
        return None


def detect_kind(scenario_dir: Path, suite_kind: str) -> str:
    has_vagrant = (scenario_dir / "Vagrantfile").is_file()
    has_dockerfile = (scenario_dir / "Dockerfile").is_file()
    has_ps1 = any(scenario_dir.glob("*.ps1"))
    if has_vagrant:
        return "vagrant-vm"
    # AutomatedLab scenarios are VMs even though they ship a Dockerfile: that
    # Dockerfile builds the Linux *bridge* container the agent works from, not
    # the target. Checked before the "mixed" logic below, which would otherwise
    # see ps1 + Dockerfile and label hivestorm/scenario-13 a "windows-container"
    # — telling users they can run an AD DC under Docker Windows containers.
    lab_os = detect_lab_os(scenario_dir)
    if lab_os:
        return f"{lab_os}-vm"
    if suite_kind == "mixed":
        if has_ps1:
            return "windows-container" if has_dockerfile else "windows-vm"
        return "linux-container"
    return suite_kind


def extract_meta(threat: Path) -> dict:
    text = threat.read_text(encoding="utf-8", errors="replace")
    title_match = TITLE_RE.search(text)
    sev_match = SEVERITY_RE.search(text) or SEVERITY_BOLD_RE.search(text)
    cvss_match = CVSS_RE.search(text)
    cves = sorted(set(CVE_RE.findall(text)))
    cwes = sorted(set(CWE_RE.findall(text)))
    return {
        "title": title_match.group(1).strip() if title_match else None,
        "severity": sev_match.group(1).capitalize() if sev_match else None,
        "cvss": float(cvss_match.group(1)) if cvss_match else None,
        "cves": cves,
        "cwes": cwes,
    }


def iter_scenarios():
    for suite_name, info in SUITES.items():
        suite_root = ROOT / info["root"]
        if not suite_root.is_dir():
            continue
        for entry in sorted(suite_root.iterdir()):
            if not entry.is_dir():
                continue
            if not entry.name.startswith("scenario"):
                continue
            threat = find_threat_doc(entry)
            kind = detect_kind(entry, info["kind"])
            verify = None
            for v in ("verify.sh", "verify.ps1", "verify-poc.sh", "verify-service.ps1"):
                if (entry / v).is_file():
                    verify = v
                    break
            launch = None
            for l in ("Dockerfile", "Vagrantfile"):
                if (entry / l).is_file():
                    launch = l
                    break
            if launch is None:
                # VM scenarios share a launcher with their siblings rather than
                # shipping one each. meta4/ad-vm/scenario-* used a parent
                # Vagrantfile; after the Hyper-V/AutomatedLab port that file is
                # gone and the dispatch contract is the parent run-scenario.sh
                # (lib/harness-schema.md). Without the second candidate all 20
                # ad-vm scenarios regenerate with "launch_file": null.
                for parent_launch in ("Vagrantfile", "run-scenario.sh"):
                    candidate = entry.parent / parent_launch
                    if candidate.is_file():
                        launch = candidate.relative_to(entry.parent).as_posix()
                        break
            scenario_id = f"{suite_name}/{entry.name}"
            record = {
                "scenario_id": scenario_id,
                "suite": suite_name,
                # as_posix(), not str(): str() yields OS-native separators, so
                # regenerating on Windows rewrote all 313 paths with backslashes
                # and produced a whole-file diff against the published manifest.
                "path": entry.relative_to(ROOT).as_posix(),
                "kind": kind,
                "launch_file": launch,
                "verify_file": verify,
                "threat_file": threat.name if threat else None,
            }
            if threat is not None:
                record.update(extract_meta(threat))
            yield record


def main() -> None:
    records = sorted(iter_scenarios(), key=lambda r: r["scenario_id"])
    with OUT.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False))
            fh.write("\n")
    digest = hashlib.sha256(OUT.read_bytes()).hexdigest()
    print(f"wrote {len(records)} records to {OUT}")
    print(f"sha256: {digest}")
    print(f"bytes:  {OUT.stat().st_size}")


if __name__ == "__main__":
    main()
