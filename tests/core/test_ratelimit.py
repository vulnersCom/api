"""Token-bucket pacing for both the sync and generated-async buckets."""

from __future__ import annotations

import asyncio

import pytest

import vulners._ratelimit as rl_sync
import vulners._ratelimit_async as rl_async
from vulners._exceptions import RateLimitError
from vulners._ratelimit import RateLimitBucket
from vulners._ratelimit_async import AsyncRateLimitBucket


class FakeClock:
    """Virtual clock: sleep advances virtual time instead of blocking."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


class FakeAsyncio:
    """asyncio stand-in: real Lock, fake (virtual-time) sleep."""

    Lock = asyncio.Lock

    def __init__(self, clock: FakeClock) -> None:
        self._clock = clock

    async def sleep(self, seconds: float) -> None:
        self._clock.sleep(seconds)


class TestSyncBucket:
    def test_pacing_sleeps_between_calls(self, monkeypatch):
        clock = FakeClock()
        monkeypatch.setattr(rl_sync, "time", clock)
        bucket = RateLimitBucket(rate=10.0, burst=1.0)  # one token; 10/s refill
        for _ in range(3):
            bucket.consume()
        # first call spends the burst token; the next two each wait ~0.1s.
        assert len(clock.slept) == 2
        assert all(abs(s - 0.1) < 1e-6 for s in clock.slept)

    def test_poisoned_header_ignored(self):
        bucket = RateLimitBucket(rate=10.0)
        bucket.update(rate=0)  # zero rate would freeze the bucket
        bucket.update(rate=float("nan"))  # NaN would poison it
        assert bucket._rate == 10.0

    def test_max_wait_raises(self):
        bucket = RateLimitBucket(rate=1.0, burst=1.0)
        bucket.consume()  # spend the token (instant)
        with pytest.raises(RateLimitError) as excinfo:
            bucket.consume(max_wait=0.5)  # next token is ~1s away, over the cap
        assert excinfo.value.retry_after is not None


class TestAsyncBucket:
    async def test_pacing_sleeps_between_calls(self, monkeypatch):
        clock = FakeClock()
        monkeypatch.setattr(rl_async, "time", clock)
        monkeypatch.setattr(rl_async, "asyncio", FakeAsyncio(clock))
        bucket = AsyncRateLimitBucket(rate=10.0, burst=1.0)
        for _ in range(3):
            await bucket.consume()
        assert len(clock.slept) == 2
        assert all(abs(s - 0.1) < 1e-6 for s in clock.slept)

    def test_poisoned_header_ignored(self):
        bucket = AsyncRateLimitBucket(rate=10.0)
        bucket.update(rate=0)
        bucket.update(rate=float("nan"))
        assert bucket._rate == 10.0

    async def test_max_wait_raises(self):
        bucket = AsyncRateLimitBucket(rate=1.0, burst=1.0)
        await bucket.consume()
        with pytest.raises(RateLimitError):
            await bucket.consume(max_wait=0.5)
