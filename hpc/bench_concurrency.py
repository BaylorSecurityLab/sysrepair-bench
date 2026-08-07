#!/usr/bin/env python3
"""Find the right INSPECT_EVAL_MAX_CONNECTIONS for a vLLM endpoint.

Sweeps concurrency levels against a running server and reports where aggregate
throughput stops improving. Past that knee you are only adding queueing delay:
tokens/sec is flat while per-request latency keeps climbing, which pushes
samples toward the harness `time_limit` without finishing the eval any sooner.

The synthetic request is shaped like a sysrepair-bench turn rather than a
generic chat completion -- a long prompt (accumulated tool output from a repair
session) and a short completion (one reasoning step plus a command). Sweeping
with short prompts would overstate the achievable concurrency, because prefill
cost is what actually saturates the GPUs here.

Usage:
    python hpc/bench_concurrency.py \
        --base-url http://localhost:8001/v1 \
        --api-key "$VLLM_API_KEY" \
        --model qwen3.5-397b

    # quick smoke against a small model
    python hpc/bench_concurrency.py --levels 1,4,16 --requests 16 ...
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from dataclasses import dataclass, asdict, field

try:
    from openai import AsyncOpenAI
except ImportError:  # pragma: no cover
    sys.exit("openai package required: cd inspect_eval && uv sync")


# Roughly 6k tokens of filler. Content is deliberately non-repetitive: with
# --enable-prefix-caching a constant prefix would be served from cache and the
# measured prefill cost would collapse to near zero, flattering the results.
def _make_prompt(seed: int, approx_tokens: int) -> str:
    lines = [
        "You are auditing a compromised Linux host. Prior tool output follows.",
        "",
    ]
    n = max(1, approx_tokens // 12)
    for i in range(n):
        v = (seed * 7919 + i * 104729) % 100000
        lines.append(
            f"[{i:05d}] pid={v % 32768} uid={v % 1000} "
            f"cmd=/usr/sbin/svc-{v % 977} state={'S' if v % 3 else 'R'} "
            f"rss={v % 8192}kB file=/var/lib/app/{v % 613}/data.bin"
        )
    lines += [
        "",
        "Name the single most suspicious entry and the one shell command you "
        "would run next. Be brief.",
    ]
    return "\n".join(lines)


@dataclass
class Result:
    ok: bool
    latency: float
    ttft: float | None
    out_tokens: int
    error: str | None = None


@dataclass
class LevelStats:
    level: int
    wall: float
    ok: int
    failed: int
    out_tokens: int
    throughput: float          # output tokens/sec, aggregate
    completions_per_min: float
    lat_mean: float
    lat_p50: float
    lat_p95: float
    ttft_p50: float | None
    errors: list[str] = field(default_factory=list)


async def _one(
    client: AsyncOpenAI, model: str, seed: int, prompt_tokens: int, max_tokens: int
) -> Result:
    start = time.perf_counter()
    ttft: float | None = None
    out = 0
    try:
        stream = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": _make_prompt(seed, prompt_tokens)}],
            max_tokens=max_tokens,
            temperature=0.7,
            stream=True,
            stream_options={"include_usage": True},
        )
        async for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                if ttft is None:
                    ttft = time.perf_counter() - start
                out += 1
            if getattr(chunk, "usage", None):
                out = chunk.usage.completion_tokens or out
        return Result(True, time.perf_counter() - start, ttft, out)
    except Exception as exc:  # noqa: BLE001 - report, don't crash the sweep
        return Result(False, time.perf_counter() - start, ttft, 0, f"{type(exc).__name__}: {exc}")


async def _run_level(
    client: AsyncOpenAI,
    model: str,
    level: int,
    requests: int,
    prompt_tokens: int,
    max_tokens: int,
) -> LevelStats:
    sem = asyncio.Semaphore(level)
    counter = 0

    async def guarded(seed: int) -> Result:
        nonlocal counter
        async with sem:
            r = await _one(client, model, seed, prompt_tokens, max_tokens)
        counter += 1
        print(f"\r  level {level:>4}  {counter}/{requests}", end="", flush=True)
        return r

    start = time.perf_counter()
    results = await asyncio.gather(*(guarded(i) for i in range(requests)))
    wall = time.perf_counter() - start
    print("\r" + " " * 40 + "\r", end="")

    ok = [r for r in results if r.ok]
    bad = [r for r in results if not r.ok]
    lats = sorted(r.latency for r in ok) or [0.0]
    ttfts = sorted(r.ttft for r in ok if r.ttft is not None)
    tokens = sum(r.out_tokens for r in ok)

    def pct(xs: list[float], p: float) -> float:
        if not xs:
            return 0.0
        return xs[min(len(xs) - 1, int(len(xs) * p))]

    return LevelStats(
        level=level,
        wall=wall,
        ok=len(ok),
        failed=len(bad),
        out_tokens=tokens,
        throughput=tokens / wall if wall else 0.0,
        completions_per_min=len(ok) / wall * 60 if wall else 0.0,
        lat_mean=statistics.fmean(lats),
        lat_p50=pct(lats, 0.50),
        lat_p95=pct(lats, 0.95),
        ttft_p50=pct(ttfts, 0.50) if ttfts else None,
        errors=sorted({r.error for r in bad if r.error})[:3],
    )


def _recommend(stats: list[LevelStats]) -> tuple[int, str]:
    """Smallest level reaching 95% of peak throughput with no errors.

    Choosing the smallest such level rather than the fastest one matters: they
    have the same throughput by construction, but the smaller level holds far
    less latency in the queue, so an individual sample is likelier to finish
    inside its per-sample time_limit.
    """
    clean = [s for s in stats if s.failed == 0 and s.ok > 0]
    if not clean:
        return 1, "every level returned errors; fix the endpoint before tuning"

    peak = max(s.throughput for s in clean)
    knee = min(
        (s for s in clean if s.throughput >= 0.95 * peak),
        key=lambda s: s.level,
    )

    saturated = [s for s in stats if s.failed > 0]
    note = (
        f"peak {peak:,.0f} tok/s; knee at {knee.level} "
        f"({knee.throughput:,.0f} tok/s, p95 {knee.lat_p95:.1f}s)"
    )
    if saturated:
        note += f"; errors began at level {min(s.level for s in saturated)}"
    else:
        note += "; no level errored, so the ceiling may be above the sweep range"
    return knee.level, note


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default="http://localhost:8001/v1")
    ap.add_argument("--api-key", required=True, help="bearer token from the job's conn_<jobid>.env")
    ap.add_argument("--model", required=True, help="value of --served-model-name")
    ap.add_argument("--levels", default="1,2,4,8,16,32,64",
                    help="comma-separated concurrency levels to sweep")
    ap.add_argument("--requests", type=int, default=0,
                    help="requests per level (default: 4x the level, min 8)")
    ap.add_argument("--prompt-tokens", type=int, default=6000)
    ap.add_argument("--max-tokens", type=int, default=300)
    ap.add_argument("--json", dest="json_out", help="write raw results here")
    args = ap.parse_args()

    levels = [int(x) for x in args.levels.split(",") if x.strip()]
    client = AsyncOpenAI(base_url=args.base_url, api_key=args.api_key, timeout=600.0, max_retries=0)

    print(f"endpoint : {args.base_url}")
    print(f"model    : {args.model}")
    print(f"workload : ~{args.prompt_tokens} prompt tok -> {args.max_tokens} completion tok\n")

    # One throwaway request: the first call after startup pays CUDA graph
    # capture and allocator warmup, which would otherwise be charged to level 1
    # and skew every ratio computed against it.
    print("warming up...", end="", flush=True)
    warm = await _one(client, args.model, 999, args.prompt_tokens, 32)
    if not warm.ok:
        print(f"\nERROR: warmup request failed -> {warm.error}")
        print("Check the tunnel is up and the API key matches.")
        return 1
    print(" ok\n")

    stats: list[LevelStats] = []
    for level in levels:
        n = args.requests or max(8, level * 4)
        stats.append(await _run_level(client, args.model, level, n, args.prompt_tokens, args.max_tokens))
        s = stats[-1]
        print(
            f"  level {s.level:>4}  {s.throughput:>8,.0f} tok/s  "
            f"{s.completions_per_min:>6.1f} req/min  "
            f"p50 {s.lat_p50:>6.1f}s  p95 {s.lat_p95:>6.1f}s  "
            f"ttft {s.ttft_p50 or 0:>5.2f}s  fail {s.failed}"
        )
        if s.errors:
            for e in s.errors:
                print(f"           ! {e[:110]}")

    best, note = _recommend(stats)
    print("\n" + "=" * 68)
    print(f"  INSPECT_EVAL_MAX_CONNECTIONS={best}")
    print(f"  {note}")
    print("=" * 68)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(
                {"recommended": best, "note": note, "levels": [asdict(s) for s in stats]},
                fh,
                indent=2,
            )
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
