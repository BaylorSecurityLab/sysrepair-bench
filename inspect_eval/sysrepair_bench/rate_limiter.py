"""Sliding-window rate limiter for capped API plans (e.g. MiniMax Token Plan).

When ``request_limit`` is 0 the limiter is a no-op — all calls pass through
instantly.  This lets the same code path serve both capped and unlimited keys.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------

class RateLimiter:
    """Async sliding-window rate limiter.

    Parameters
    ----------
    request_limit:
        Maximum requests allowed in the window.  0 = unlimited (no-op).
    window_seconds:
        Window size in seconds.  Default 18 000 (5 hours).
    """

    def __init__(self, request_limit: int = 0, window_seconds: int = 18_000) -> None:
        self.request_limit = request_limit
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque()

    async def acquire(self) -> None:
        """Wait until a request slot is available, then record it."""
        if self.request_limit <= 0:
            return  # unlimited — no-op

        while True:
            now = time.monotonic()
            # Evict expired timestamps.
            while self._timestamps and self._timestamps[0] <= now - self.window_seconds:
                self._timestamps.popleft()

            if len(self._timestamps) < self.request_limit:
                self._timestamps.append(now)
                remaining = self.request_limit - len(self._timestamps)
                if remaining <= self.request_limit * 0.1:
                    log.warning(
                        "Rate limiter: %d / %d requests remaining in window",
                        remaining,
                        self.request_limit,
                    )
                return

            # Window full — sleep until the oldest entry expires.
            sleep_for = self._timestamps[0] - (now - self.window_seconds) + 0.1
            log.info(
                "Rate limiter: window full (%d/%d). Sleeping %.1fs.",
                len(self._timestamps),
                self.request_limit,
                sleep_for,
            )
            await asyncio.sleep(sleep_for)

    @property
    def remaining(self) -> int:
        """Requests remaining in the current window."""
        if self.request_limit <= 0:
            return -1  # unlimited
        now = time.monotonic()
        while self._timestamps and self._timestamps[0] <= now - self.window_seconds:
            self._timestamps.popleft()
        return self.request_limit - len(self._timestamps)


# ---------------------------------------------------------------------------
# Global singleton — one limiter shared across all solvers in a run
# ---------------------------------------------------------------------------

_instance: RateLimiter | None = None


def init_rate_limiter(request_limit: int = 0, window_seconds: int = 18_000) -> RateLimiter:
    """Create (or replace) the global rate limiter."""
    global _instance
    _instance = RateLimiter(request_limit=request_limit, window_seconds=window_seconds)
    log.info(
        "Rate limiter initialised: %s requests / %ds window",
        request_limit or "unlimited",
        window_seconds,
    )
    return _instance


def get_rate_limiter() -> RateLimiter:
    """Return the global rate limiter.  Falls back to a no-op if not initialised."""
    global _instance
    if _instance is None:
        _instance = RateLimiter()  # no-op default
    return _instance
