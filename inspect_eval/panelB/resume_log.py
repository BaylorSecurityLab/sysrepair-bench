"""Resume an interrupted sysrepair-bench eval log (re-runs only the incomplete
samples). Runs inside the package so the docker sandbox provider + task are
registered — the bare `inspect eval-retry` CLI cannot deserialize our sandbox.

Usage:
    OPENAI_API_KEY=... OPENAI_BASE_URL=... \
      uv run python panelB/resume_log.py <log.eval> [max_connections]
"""
import sys

import sysrepair_bench  # noqa: F401  registers docker sandbox + sysrepair_bench task
from inspect_ai import eval_retry

log = sys.argv[1]
mc = int(sys.argv[2]) if len(sys.argv) > 2 else 24
eval_retry(
    log,
    max_connections=mc,
    retry_on_error=1,
    fail_on_error=0.2,
)
