"""Tests for the sliding-window rate limiter."""

import asyncio
import time

import pytest

from sysrepair_bench.rate_limiter import RateLimiter


@pytest.mark.asyncio
async def test_no_limit_is_noop():
    """When request_limit=0, acquire() never blocks."""
    rl = RateLimiter(request_limit=0, window_seconds=300)
    for _ in range(100):
        await rl.acquire()
    # Should complete instantly — no blocking.


@pytest.mark.asyncio
async def test_under_limit_does_not_block():
    """Requests under the limit complete without delay."""
    rl = RateLimiter(request_limit=10, window_seconds=300)
    start = time.monotonic()
    for _ in range(10):
        await rl.acquire()
    elapsed = time.monotonic() - start
    assert elapsed < 0.5, f"Should not block, took {elapsed:.2f}s"


@pytest.mark.asyncio
async def test_over_limit_blocks():
    """The 11th request in a 10-request window blocks until the window slides."""
    # Use a tiny window so the test doesn't take 5 hours.
    rl = RateLimiter(request_limit=3, window_seconds=1)
    for _ in range(3):
        await rl.acquire()
    # 4th call should block ~1s until the first request expires.
    start = time.monotonic()
    await rl.acquire()
    elapsed = time.monotonic() - start
    assert 0.8 < elapsed < 2.0, f"Expected ~1s block, got {elapsed:.2f}s"


@pytest.mark.asyncio
async def test_status_reports_remaining():
    rl = RateLimiter(request_limit=10, window_seconds=300)
    assert rl.remaining == 10
    await rl.acquire()
    assert rl.remaining == 9


@pytest.mark.asyncio
async def test_global_singleton_returns_same_instance():
    """get_rate_limiter() returns the same instance after init."""
    from sysrepair_bench.rate_limiter import get_rate_limiter, init_rate_limiter

    init_rate_limiter(request_limit=100, window_seconds=300)
    a = get_rate_limiter()
    b = get_rate_limiter()
    assert a is b
