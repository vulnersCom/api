"""Pins and regression tests for the X-Vulners-Ratelimit-Reqlimit handling
and the token bucket.

Low (<60 req/min) and zero/garbage limit headers are handled:
they no longer hang consume() forever or crash with ZeroDivisionError, so they
are exercised directly here.
"""

from __future__ import annotations

import pytest

import vulners.base
from vulners.base import RateLimitBucket, VulnersApiBase


class _BoundedClock:
    """Virtual clock whose ``sleep`` advances time but raises after a cap.

    A regressed infinite ``consume()`` loop then fails fast (AssertionError)
    instead of hanging the whole test session.
    """

    def __init__(self, start: float = 1000.0, max_sleeps: int = 100000):
        self.now = start
        self.sleeps: list[float] = []
        self._max = max_sleeps

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        if len(self.sleeps) >= self._max:
            raise AssertionError("consume() did not terminate (rate-limit hang)")
        self.sleeps.append(seconds)
        self.now += seconds


def _install_clock(monkeypatch, clock: _BoundedClock) -> None:
    monkeypatch.setattr(vulners.base, "monotonic", clock.monotonic)
    monkeypatch.setattr(vulners.base, "sleep", clock.sleep)


@pytest.fixture
def bounded_clock(monkeypatch):
    clock = _BoundedClock()
    _install_clock(monkeypatch, clock)
    return clock


class TestRatelimitHeader:
    def test_valid_header_updates_bucket_rate(self, api, server):
        server.enqueue_envelope({}, headers={"X-Vulners-Ratelimit-Reqlimit": "120"})
        api._invoke("GET", "/synthetic/rl", {}, ())
        bucket = api._ratelimits["/synthetic/rl"]
        assert bucket._rate == pytest.approx(2.0)  # 120 requests/min

    def test_garbage_header_is_ignored(self, api, server):
        server.enqueue_envelope({}, headers={"X-Vulners-Ratelimit-Reqlimit": "abc"})
        api._invoke("GET", "/synthetic/rl-garbage", {}, ())
        bucket = api._ratelimits["/synthetic/rl-garbage"]
        assert bucket._rate == pytest.approx(1000.0)  # unchanged (test fixture rate)

    def test_missing_header_keeps_rate(self, api, server):
        server.enqueue_envelope({})
        api._invoke("GET", "/synthetic/rl-missing", {}, ())
        assert api._ratelimits["/synthetic/rl-missing"]._rate == pytest.approx(1000.0)

    def test_vscanner_buckets_grouped_by_ratelimit_key(self, make_api, server):
        vapi = make_api(vulners.VScannerApi)
        vapi._invoke("GET", "/api/v3/useraction/licenseids", {}, ())
        assert "vscanner" in vapi._ratelimits
        assert "/api/v3/useraction/licenseids" not in vapi._ratelimits


class TestBucketPacing:
    def test_burst_then_paced_consume_with_fake_clock(self, fake_clock):
        bucket = RateLimitBucket(rate=10.0)
        bucket.consume()  # burst token: no sleep
        assert fake_clock.sleeps == []
        bucket.consume()  # must pace: sleep (1 - allowance) / rate
        # refill float error may add residual micro-sleeps; assert on totals
        assert len(fake_clock.sleeps) >= 1
        assert fake_clock.sleeps[0] == pytest.approx(0.1)
        assert sum(fake_clock.sleeps) == pytest.approx(0.1)

    def test_sleep_advances_virtual_time_only(self, fake_clock):
        start = fake_clock.now
        bucket = RateLimitBucket(rate=2.0)
        bucket.consume()
        bucket.consume()
        assert fake_clock.now == pytest.approx(start + 0.5)


class TestLowLimitDoesNotHang:
    """A server limit below 60 req/min (rate < 1 token/s) must still let
    consume() pace and terminate, not clamp the burst below one token."""

    # Exact binary fractions (30, 15, 7.5 req/min): the fake clock terminates
    # cleanly without the sub-ULP residual sleeps a non-exact rate would spin on
    # at this virtual epoch (a fake-clock artifact; a real monotonic clock always
    # advances past it).
    @pytest.mark.parametrize("rate", [0.5, 0.25, 0.125])
    def test_bucket_below_1_token_per_second_terminates(self, bounded_clock, rate):
        bucket = RateLimitBucket(rate=rate)
        bucket.consume()  # burst token: no sleep
        bucket.consume()  # must pace and must terminate
        assert bounded_clock.sleeps  # it did pace
        # spacing between the two paced tokens is ~ 1/rate seconds
        assert bounded_clock.sleeps[0] == pytest.approx(1.0 / rate)

    def test_second_invoke_after_low_limit_header_terminates(
        self, monkeypatch, api, server
    ):
        # Integration: a '30' limit header retunes the per-instance bucket to
        # 0.5 req/s; a second call to the same URL must still terminate.
        clock = _BoundedClock()
        _install_clock(monkeypatch, clock)
        server.enqueue_envelope({}, headers={"X-Vulners-Ratelimit-Reqlimit": "30"})
        server.enqueue_envelope({})
        api._invoke("GET", "/synthetic/low", {}, ())
        assert api._ratelimits["/synthetic/low"]._rate == pytest.approx(0.5)
        api._invoke("GET", "/synthetic/low", {}, ())  # must terminate
        assert len(server.requests) == 2


class TestRatelimitHeaderValidation:
    """The Reqlimit header is server-controlled data. Zero, negative,
    sub-1-rpm and non-finite values are ignored instead of freezing/crashing."""

    @pytest.mark.parametrize("value", ["0", "-60", "0.01", "inf", "nan"])
    def test_bad_header_is_ignored_and_next_call_survives(self, api, server, value):
        server.enqueue_envelope({}, headers={"X-Vulners-Ratelimit-Reqlimit": value})
        api._invoke("GET", "/synthetic/bad", {}, ())
        bucket = api._ratelimits["/synthetic/bad"]
        assert bucket._rate == pytest.approx(1000.0)  # unchanged (fixture rate)
        # the follow-up call must not hang or raise ZeroDivisionError
        server.enqueue_envelope({})
        api._invoke("GET", "/synthetic/bad", {}, ())
        assert len(server.requests) == 2

    def test_boundary_limit_1_is_applied(self, api, server):
        # exactly 1 req/min is the floor and must be applied (catches > vs >=)
        server.enqueue_envelope({}, headers={"X-Vulners-Ratelimit-Reqlimit": "1"})
        api._invoke("GET", "/synthetic/one", {}, ())
        bucket = api._ratelimits["/synthetic/one"]
        assert bucket._rate == pytest.approx(1.0 / 60.0)

    def test_valid_high_limit_still_applied(self, api, server):
        # regression of the success path: 120 req/min -> 2.0 tokens/s
        server.enqueue_envelope({}, headers={"X-Vulners-Ratelimit-Reqlimit": "120"})
        api._invoke("GET", "/synthetic/ok", {}, ())
        assert api._ratelimits["/synthetic/ok"]._rate == pytest.approx(2.0)


class TestBucketGuards:
    """Direct guards on update()/consume() against poisoned rates."""

    @pytest.mark.parametrize("bad_rate", [0.0, -5.0, float("nan")])
    def test_update_ignores_nonpositive_or_nan_rate(self, bad_rate):
        bucket = RateLimitBucket(rate=10.0)
        bucket.update(rate=bad_rate)
        assert bucket._rate == pytest.approx(10.0)  # unchanged

    def test_consume_with_zero_rate_does_not_divide_by_zero(self):
        bucket = RateLimitBucket(rate=0.0)  # e.g. a poisoned bucket
        bucket.consume()  # must return, not raise ZeroDivisionError


class TestMonotonicClock:
    """The bucket must use a monotonic clock and clamp negative deltas, so
    wall-clock steps (NTP correction, DST) can't freeze or over-credit it."""

    def test_module_uses_monotonic_not_wall_clock(self):
        # early-bound import: base.py did `from time import monotonic, sleep`
        assert not hasattr(vulners.base, "time")
        assert hasattr(vulners.base, "monotonic")

    def test_backward_clock_step_does_not_freeze(self, fake_clock):
        bucket = RateLimitBucket(rate=10.0)
        bucket.consume()  # allowance -> 0, _last_check = now
        # clock jumps backward (or a racing thread moved _last_check ahead):
        # the negative delta must contribute 0 refill, not -1200.
        fake_clock.now -= 120.0
        bucket.consume()
        # it paced normally (~0.1s) instead of freezing for ~120s
        assert sum(fake_clock.sleeps) == pytest.approx(0.1)
        assert bucket._allowance == pytest.approx(0.0)

    def test_forward_clock_jump_capped_at_burst(self, fake_clock):
        bucket = RateLimitBucket(rate=10.0)
        bucket.consume()  # allowance -> 0
        fake_clock.now += 3600.0  # huge forward jump
        bucket.consume()  # refill is capped at burst, no unbounded credit
        assert bucket._burst == pytest.approx(1.0)
        assert bucket._allowance == pytest.approx(0.0)  # burst(1.0) - 1
        assert fake_clock.sleeps == []  # burst token available, no pacing


class TestBucketLocking:
    """consume()/update() serialize accounting under a lock, and the
    sleep happens outside the lock so it can't block other threads."""

    def test_bucket_has_a_lock(self):
        bucket = RateLimitBucket(rate=10.0)
        assert bucket._lock.acquire(blocking=False)
        bucket._lock.release()

    def test_lock_is_released_during_sleep(self, monkeypatch):
        bucket = RateLimitBucket(rate=10.0)
        clock = _BoundedClock()
        lock_free_during_sleep: list[bool] = []

        def spy_sleep(seconds: float) -> None:
            acquired = bucket._lock.acquire(blocking=False)
            lock_free_during_sleep.append(acquired)
            if acquired:
                bucket._lock.release()
            clock.sleep(seconds)

        monkeypatch.setattr(vulners.base, "monotonic", clock.monotonic)
        monkeypatch.setattr(vulners.base, "sleep", spy_sleep)
        bucket.consume()  # burst token: no sleep
        bucket.consume()  # paces -> sleeps once; lock must be free then
        assert lock_free_during_sleep == [True]

    def test_concurrent_consume_and_update_no_deadlock(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor

        bucket = RateLimitBucket(rate=1000.0)  # high rate -> negligible pacing
        n = 8
        barrier = threading.Barrier(n)
        errors: list[Exception] = []

        def worker(i: int) -> None:
            try:
                barrier.wait()
                for _ in range(50):
                    if i % 2:
                        bucket.update(rate=1000.0)  # rate >= 1 only
                    else:
                        bucket.consume()
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=n) as ex:
            futures = [ex.submit(worker, i) for i in range(n)]
            for f in futures:
                f.result(timeout=10)  # a deadlock would raise TimeoutError
        assert errors == []

    def test_threadpool_invoke_is_thread_safe(self, make_api, server):
        from concurrent.futures import ThreadPoolExecutor

        api = make_api()
        n = 16

        def call() -> object:
            return api._invoke("GET", "/synthetic/pool", {}, ())

        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = [ex.submit(call) for _ in range(n)]
            results = [f.result(timeout=10) for f in futures]
        assert len(server.requests) == n
        assert all(r == {} for r in results)


class TestPerInstanceRatelimits:
    """Rate-limit buckets live per instance, not in a shared class dict, so
    one api key/instance can no longer throttle or wedge another."""

    def test_no_class_level_ratelimits(self):
        assert not hasattr(VulnersApiBase, "_ratelimits")

    def test_instances_have_independent_bucket_dicts(self, make_api):
        a = make_api()
        b = make_api()
        assert a._ratelimits is not b._ratelimits

    def test_header_on_one_instance_does_not_affect_another(self, make_api, server):
        a = make_api()
        b = make_api()
        # 'a' receives a '120' limit on a URL; 'b' must not inherit it.
        server.enqueue_envelope({}, headers={"X-Vulners-Ratelimit-Reqlimit": "120"})
        a._invoke("GET", "/synthetic/shared", {}, ())
        b._invoke("GET", "/synthetic/shared", {}, ())  # queue empty -> default
        assert a._ratelimits["/synthetic/shared"]._rate == pytest.approx(2.0)
        assert b._ratelimits["/synthetic/shared"]._rate == pytest.approx(1000.0)

    def test_bucket_persists_across_calls_on_same_instance(self, make_api):
        api = make_api()
        api._invoke("GET", "/synthetic/persist", {}, ())
        first = api._ratelimits["/synthetic/persist"]
        api._invoke("GET", "/synthetic/persist", {}, ())
        # setdefault reuses the same bucket, so throttling state is preserved
        assert api._ratelimits["/synthetic/persist"] is first

    def test_bucket_built_only_on_miss_not_every_call(self, make_api, monkeypatch):
        # The hot path must not construct (and immediately discard) a fresh
        # RateLimitBucket on every request: a repeated key builds exactly one.
        api = make_api()
        built = 0
        real_bucket_cls = vulners.base.RateLimitBucket

        class CountingBucket(real_bucket_cls):
            def __init__(self, *a, **kw):
                nonlocal built
                built += 1
                super().__init__(*a, **kw)

        monkeypatch.setattr(vulners.base, "RateLimitBucket", CountingBucket)
        for _ in range(5):
            api._invoke("GET", "/synthetic/count", {}, ())
        assert built == 1
        assert isinstance(api._ratelimits["/synthetic/count"], real_bucket_cls)

    def test_concurrent_first_use_creates_single_bucket(self, make_api):
        import threading
        from concurrent.futures import ThreadPoolExecutor

        api = make_api()
        n = 10
        barrier = threading.Barrier(n)

        def call() -> None:
            barrier.wait()
            api._invoke("GET", "/synthetic/race", {}, ())

        with ThreadPoolExecutor(max_workers=n) as ex:
            for f in [ex.submit(call) for _ in range(n)]:
                f.result(timeout=10)
        # setdefault is atomic in CPython: exactly one bucket for the key
        assert list(api._ratelimits) == ["/synthetic/race"]
