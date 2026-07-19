"""Async token-bucket rate limiter (unasyncd source for the sync bucket).

This module is the async source of truth. ``unasyncd`` generates the sync
sibling ``vulners/_ratelimit.py`` from it (the async lock and sleep become their
threading/time equivalents and the class is renamed to ``RateLimitBucket``), so
the two stay behaviourally identical by construction. Edit this file only;
regenerate with ``uv run unasyncd`` (checked by ``unasyncd --check`` in CI).

Ported from ``vulners.base.RateLimitBucket``: per-instance, ``time.monotonic``,
lock-guarded accounting, sleeps performed outside the lock.
"""

from __future__ import annotations

import asyncio
import time

from ._exceptions import RateLimitError


class AsyncRateLimitBucket:
    """An implementation of the Token Bucket algorithm."""

    def __init__(self, rate: float = 10.0, burst: float = 1.0) -> None:
        # Serializes access to the mutable accounting fields; the bucket may be
        # shared between tasks.
        self._lock = asyncio.Lock()
        self._rate = float(rate)
        # Never clamp the burst below one whole token: with burst < 1 the
        # allowance can never reach the price of a request and consume() would
        # loop forever for any server limit below 60 req/min.
        self._burst = max(1.0, min(float(burst), self._rate))
        self._allowance = self._burst
        self._last_check = time.monotonic()

    def update(self, rate: float, burst: float = 1.0) -> None:
        # Ignore non-positive / NaN rates (poisoned server header). Written as
        # "not (rate > 0)" so NaN is rejected too.
        if not (rate > 0):
            return
        self._rate = float(rate)
        self._burst = max(1.0, min(float(burst), self._rate))

    async def consume(self, max_wait: float | None = None) -> None:
        # A non-positive / NaN rate would divide by zero in the sleep below;
        # skip pacing entirely in that case.
        if not (self._rate > 0):
            return
        waited = 0.0
        while True:
            async with self._lock:
                now = time.monotonic()
                # number of seconds since the last call
                delta = now - self._last_check
                self._last_check = now
                # increase the number of allowed calls; clamp a negative delta
                # to 0 so a backward clock step (or a racing task that moved
                # _last_check ahead) can't freeze the bucket
                self._allowance += max(delta, 0.0) * self._rate
                if self._allowance > self._burst:
                    # don't allow more than "burst" calls
                    self._allowance = self._burst
                if self._allowance >= 1:
                    self._allowance -= 1
                    return
                # cool down
                delay = (1 - self._allowance) / self._rate
            # Refuse to block longer than the caller's ceiling.
            if max_wait is not None and waited + delay > max_wait:
                raise RateLimitError(
                    f"rate-limit pacing would exceed max_rate_limit_wait ({max_wait}s)",
                    status_code=429,
                    retry_after=delay,
                )
            # sleep OUTSIDE the lock so other tasks aren't blocked, then re-enter
            # and recompute the allowance
            await asyncio.sleep(delay)
            waited += delay
