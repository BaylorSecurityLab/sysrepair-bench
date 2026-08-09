"""The PowerShell edition of the two-component protocol.

Mirrors test_two_component_verdict.py. The Windows verifiers are the last 27 in
the corpus and they are the ones most likely to drift from the shell library,
because nothing forces the two implementations to agree -- scorer.py parses
whatever either of them emits. These tests pin the agreement.

The execution tests need Windows PowerShell and are skipped elsewhere; the
inlining and parsing tests run everywhere.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sysrepair_bench.scorer import (  # noqa: E402
    _inline_verifylib,
    _parse_verdict_summary,
)

_REPO = Path(__file__).resolve().parents[2]
_LIB_PS1 = _REPO / "lib" / "verifylib.ps1"

_GUARD = (
    "if (-not $global:SysRepairVerifyLibLoaded) { . \"$(if ($env:SYSREPAIR_VERIFYLIB) "
    "{ $env:SYSREPAIR_VERIFYLIB } else { 'C:\\verifylib.ps1' })\" }"
)

_PWSH = shutil.which("powershell.exe")
requires_powershell = pytest.mark.skipif(
    _PWSH is None, reason="Windows PowerShell not available on this host"
)


def _run(script: str, tmp_path: Path) -> subprocess.CompletedProcess:
    p = tmp_path / "verify.ps1"
    p.write_text(script, encoding="utf-8")
    return subprocess.run(
        [_PWSH, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(p)],
        capture_output=True, text=True, timeout=120,
    )


def _records(out: str) -> list[dict]:
    recs = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{"):
            recs.append(json.loads(line))
    return recs


class TestInlining:
    def test_ps1_gets_the_powershell_library(self):
        out = _inline_verifylib(_GUARD + "\nComplete-Verify\n", "powershell")
        assert "verifylib.ps1" in out
        assert "$global:SysRepairVerifyLibLoaded = $true" in out
        # The shell library must not leak into a PowerShell verifier.
        assert "_sr_json_escape()" not in out

    def test_sh_still_gets_the_shell_library(self):
        src = '. "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"\nverify_finish\n'
        out = _inline_verifylib(src, "sh")
        assert "verifylib.sh" in out
        assert "record_poc()" in out

    def test_unmigrated_ps1_untouched(self):
        legacy = "Write-Host 'hi'\nexit 0\n"
        assert _inline_verifylib(legacy, "powershell") == legacy

    def test_missing_library_fails_closed(self, monkeypatch):
        import sysrepair_bench.scorer as sc

        monkeypatch.setattr(sc, "_VERIFYLIB_PS1", Path("/nonexistent/verifylib.ps1"))
        with pytest.raises(RuntimeError):
            sc._inline_verifylib(_GUARD + "\nComplete-Verify\n", "powershell")


@requires_powershell
class TestExecution:
    def test_inlined_guard_never_reads_the_planted_file(self, tmp_path, monkeypatch):
        """The security property: a poisoned library on disk must be ignored."""
        poison = tmp_path / "verifylib.ps1"
        poison.write_text(
            "$global:SysRepairVerifyLibLoaded = $true\n"
            "function global:Record-Poc { }\n"
            "function global:Complete-Verify { exit 0 }\n",
            encoding="utf-8",
        )
        script = _inline_verifylib(
            _GUARD + "\nRecord-Poc still_vulnerable 0 'not fixed'\nComplete-Verify\n",
            "powershell",
        )
        p = tmp_path / "verify.ps1"
        p.write_text(script, encoding="utf-8")
        r = subprocess.run(
            [_PWSH, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(p)],
            capture_output=True, text=True, timeout=120,
            env={**dict(__import__("os").environ), "SYSREPAIR_VERIFYLIB": str(poison)},
        )
        # The real library ran, so the failing check is reported and the exit
        # code is FAIL -- not the stub's unconditional 0.
        assert r.returncode == 1, r.stdout
        assert any(x.get("id") == "still_vulnerable" for x in _records(r.stdout))

    def test_exit_codes_match_v1(self, tmp_path):
        base = f"$env:SYSREPAIR_VERIFYLIB='{_LIB_PS1.as_posix()}'\n{_GUARD}\n"
        allpass = _run(base + "Record-Poc a 1\nRecord-Reg b 1\nComplete-Verify\n", tmp_path)
        assert allpass.returncode == 0
        onefail = _run(base + "Record-Poc a 0\nRecord-Reg b 1\nComplete-Verify\n", tmp_path)
        assert onefail.returncode == 1
        skip = _run(base + "Skip-NotApplicable 'no such service here'\n", tmp_path)
        assert skip.returncode == 42

    def test_components_are_independent(self, tmp_path):
        """The whole point: poc-fail/reg-pass must be distinguishable."""
        base = f"$env:SYSREPAIR_VERIFYLIB='{_LIB_PS1.as_posix()}'\n{_GUARD}\n"
        r = _run(base + "Record-Poc a 0 'still open'\nRecord-Reg b 1\nComplete-Verify\n", tmp_path)
        s = _parse_verdict_summary(r.stdout)
        assert s["security_pass"] is False
        assert s["regression_pass"] is True

        r = _run(base + "Record-Poc a 1\nRecord-Reg b 0 'service down'\nComplete-Verify\n", tmp_path)
        s = _parse_verdict_summary(r.stdout)
        assert s["security_pass"] is True
        assert s["regression_pass"] is False

    def test_missing_component_reports_null_not_true(self, tmp_path):
        """A verifier with no PoC checks must not claim a security pass."""
        base = f"$env:SYSREPAIR_VERIFYLIB='{_LIB_PS1.as_posix()}'\n{_GUARD}\n"
        r = _run(base + "Record-Reg b 1\nComplete-Verify\n", tmp_path)
        s = _parse_verdict_summary(r.stdout)
        assert s["security_pass"] is None
        assert s["regression_pass"] is True

    def test_only_explicit_true_passes(self, tmp_path):
        """A typo or empty value must read as FAIL, never as credit."""
        base = f"$env:SYSREPAIR_VERIFYLIB='{_LIB_PS1.as_posix()}'\n{_GUARD}\n"
        r = _run(base + "Record-Poc a ''\nRecord-Poc b 'yes'\nRecord-Poc c $null\n"
                        "Record-Reg d 1\nComplete-Verify\n", tmp_path)
        s = _parse_verdict_summary(r.stdout)
        assert s["poc_failed"] == 3, r.stdout

    def test_detail_strings_round_trip(self, tmp_path):
        r"""Windows details are full of backslashes; C:\a\b must survive."""
        base = f"$env:SYSREPAIR_VERIFYLIB='{_LIB_PS1.as_posix()}'\n{_GUARD}\n"
        r = _run(base + "Record-Poc a 0 'C:\\Windows\\System32 said \"no\"'\n"
                        "Record-Reg b 1\nComplete-Verify\n", tmp_path)
        detail = next(x["detail"] for x in _records(r.stdout) if x.get("id") == "a")
        assert detail == 'C:\\Windows\\System32 said "no"'

    def test_checks_do_not_abort_the_script(self, tmp_path):
        """Fail-fast removal: a failing check must not stop later checks."""
        base = f"$env:SYSREPAIR_VERIFYLIB='{_LIB_PS1.as_posix()}'\n{_GUARD}\n"
        r = _run(base + "$ErrorActionPreference='Stop'\n"
                        "Record-Poc a 0 'fails first'\n"
                        "Record-RegCmd b { Get-Item 'C:\\nope\\nope' }\n"
                        "Record-Reg c 1 'still reached'\nComplete-Verify\n", tmp_path)
        ids = [x.get("id") for x in _records(r.stdout)]
        assert ids[:3] == ["a", "b", "c"], r.stdout
        s = _parse_verdict_summary(r.stdout)
        assert s["poc_total"] == 1 and s["reg_total"] == 2

    def test_no_checks_recorded_fails_closed(self, tmp_path):
        base = f"$env:SYSREPAIR_VERIFYLIB='{_LIB_PS1.as_posix()}'\n{_GUARD}\n"
        r = _run(base + "Complete-Verify\n", tmp_path)
        assert r.returncode == 1
