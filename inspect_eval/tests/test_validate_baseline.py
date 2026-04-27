"""Unit tests for validate_baseline discovery and helper logic."""

import json
import os
import tempfile
from pathlib import Path

import pytest

# These imports will fail until Task 1 implementation is done — that's expected.
from validate_baseline import discover_scenarios, needs_privileged, make_image_tag


# ---------------------------------------------------------------------------
# discover_scenarios
# ---------------------------------------------------------------------------

def _make_scenario(root: Path, bench: str, name: str, privileged: bool = False) -> Path:
    """Create a minimal fake scenario directory."""
    p = root / bench / name
    p.mkdir(parents=True)
    (p / "Dockerfile").write_text("FROM scratch\n")
    (p / "verify.sh").write_text("#!/bin/bash\nexit 1\n")
    if privileged:
        (p / ".needs-privileged").touch()
    return p


def test_discover_returns_all_scenarios(tmp_path):
    _make_scenario(tmp_path, "ccdc", "scenario-01")
    _make_scenario(tmp_path, "ccdc", "scenario-02")
    _make_scenario(tmp_path, "vulnhub", "scenario-01")

    results = discover_scenarios(
        root=tmp_path,
        benchmarks=["ccdc", "vulnhub"],
        exclude=[],
    )
    names = [(r["bench"], r["name"]) for r in results]
    assert ("ccdc", "scenario-01") in names
    assert ("ccdc", "scenario-02") in names
    assert ("vulnhub", "scenario-01") in names
    assert len(results) == 3


def test_discover_excludes_specified_scenarios(tmp_path):
    _make_scenario(tmp_path, "meta4", "scenario-19")
    _make_scenario(tmp_path, "meta4", "scenario-21")
    _make_scenario(tmp_path, "meta4", "scenario-22")
    _make_scenario(tmp_path, "meta4", "scenario-01")

    results = discover_scenarios(
        root=tmp_path,
        benchmarks=["meta4"],
        exclude=["meta4/scenario-19", "meta4/scenario-21", "meta4/scenario-22"],
    )
    names = [r["name"] for r in results]
    assert "scenario-01" in names
    assert "scenario-19" not in names
    assert "scenario-21" not in names
    assert "scenario-22" not in names
    assert len(results) == 1


def test_discover_ignores_non_scenario_dirs(tmp_path):
    """Directories not matching scenario-NN are skipped."""
    (tmp_path / "ccdc" / "_base").mkdir(parents=True)
    (tmp_path / "ccdc" / "README.md").touch()
    _make_scenario(tmp_path, "ccdc", "scenario-01")

    results = discover_scenarios(root=tmp_path, benchmarks=["ccdc"], exclude=[])
    assert len(results) == 1
    assert results[0]["name"] == "scenario-01"


def test_discover_nested_benchmark(tmp_path):
    """meta3/ubuntu is a nested benchmark path."""
    _make_scenario(tmp_path, "meta3/ubuntu", "scenario-01")

    results = discover_scenarios(
        root=tmp_path,
        benchmarks=["meta3/ubuntu"],
        exclude=[],
    )
    assert len(results) == 1
    assert results[0]["bench"] == "meta3/ubuntu"


def test_discover_sorts_numerically(tmp_path):
    """scenario-9 must sort before scenario-10, not after (lexicographic trap)."""
    _make_scenario(tmp_path, "ccdc", "scenario-9")
    _make_scenario(tmp_path, "ccdc", "scenario-10")

    results = discover_scenarios(root=tmp_path, benchmarks=["ccdc"], exclude=[])
    names = [r["name"] for r in results]
    assert names == ["scenario-9", "scenario-10"]


# ---------------------------------------------------------------------------
# needs_privileged
# ---------------------------------------------------------------------------

def test_needs_privileged_true(tmp_path):
    p = _make_scenario(tmp_path, "meta4", "scenario-23", privileged=True)
    assert needs_privileged(p) is True


def test_needs_privileged_false(tmp_path):
    p = _make_scenario(tmp_path, "ccdc", "scenario-01", privileged=False)
    assert needs_privileged(p) is False


# ---------------------------------------------------------------------------
# make_image_tag
# ---------------------------------------------------------------------------

def test_make_image_tag_simple():
    tag = make_image_tag("ccdc", "scenario-01")
    assert tag == "sysrepair/ccdc-scenario-01"


def test_make_image_tag_nested():
    tag = make_image_tag("meta3/ubuntu", "scenario-05")
    assert tag == "sysrepair/meta3-ubuntu-scenario-05"
