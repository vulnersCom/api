"""Shared fixtures for the vulners SDK test suite.

All mock data is synthetic: fake API keys, fake IDs (CVE-2099-*, SYNTHETIC*),
fake documents. Only the *shape* of responses mirrors the real server
envelopes (v3: {"result": "OK", "data": ...}; v4: {"result": ...}).
"""

from __future__ import annotations

from typing import Any

import httpx
import orjson
import pytest

import vulners
import vulners.base
from vulners.base import RateLimitBucket, VulnersApiBase, VulnersApiTransport

TEST_API_KEY = "SYNTHETIC-TEST-KEY-0000000000"


@pytest.fixture(autouse=True)
def _fast_ratelimits(monkeypatch):
    """Keep the per-instance rate-limit buckets fast so tests don't really sleep.

    Each instance owns its ``_ratelimits`` dict (set in ``__init__``),
    so cross-test coupling is already gone. ``_invoke`` creates each bucket via
    ``RateLimitBucket()`` (default 10 req/s); patch the class the module looks
    up so the default rate is high enough that pacing sleeps stay negligible.
    Tests that construct buckets explicitly are unaffected (they import the real
    class and pass their own rate).
    """

    class _FastBucket(RateLimitBucket):
        def __init__(self, rate: float = 1000.0, burst: float = 1.0):
            super().__init__(rate, burst)

    monkeypatch.setattr(vulners.base, "RateLimitBucket", _FastBucket)


class FakeClock:
    """Virtual time source; ``sleep`` advances virtual time instead of blocking.

    The epoch is kept small (1000.0): the bucket refill math loses precision
    against large timestamps and the residual micro-sleeps it produces must
    still advance ``now`` (float ULP), otherwise consume() would spin forever.
    """

    def __init__(self, start: float = 1000.0):
        self.now = start
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def fake_clock(monkeypatch):
    """Install a fake clock into vulners.base.

    base.py does ``from time import monotonic, sleep``, so the names to
    patch are the *module attributes* ``vulners.base.monotonic`` /
    ``vulners.base.sleep``. Buckets must be created *after* the fake clock is
    installed (their ``_last_check`` is captured at construction time).
    """
    clock = FakeClock()
    monkeypatch.setattr(vulners.base, "monotonic", clock.monotonic)
    monkeypatch.setattr(vulners.base, "sleep", clock.sleep)
    return clock


class MockServer:
    """Programmable httpx.MockTransport handler that records every request."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self._queue: list[httpx.Response] = []

    # -- response builders (content-type is exact, no charset — pinned) --

    @staticmethod
    def json_response(
        payload: Any, status_code: int = 200, headers: dict[str, str] | None = None
    ) -> httpx.Response:
        hdrs = {"content-type": "application/json"}
        if headers:
            hdrs.update(headers)
        return httpx.Response(status_code, content=orjson.dumps(payload), headers=hdrs)

    @classmethod
    def envelope_response(
        cls,
        data: Any,
        result: str = "OK",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """v3 envelope: {"result": ..., "data": ...}."""
        return cls.json_response({"result": result, "data": data}, status_code, headers)

    @staticmethod
    def raw_response(
        content: bytes,
        content_type: str,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        hdrs = {"content-type": content_type}
        if headers:
            hdrs.update(headers)
        return httpx.Response(status_code, content=content, headers=hdrs)

    # -- queue management --

    def enqueue(self, response: httpx.Response) -> None:
        self._queue.append(response)

    def enqueue_json(self, payload: Any, status_code: int = 200, **kw: Any) -> None:
        self.enqueue(self.json_response(payload, status_code, **kw))

    def enqueue_envelope(self, data: Any, status_code: int = 200, **kw: Any) -> None:
        self.enqueue(self.envelope_response(data, status_code=status_code, **kw))

    def enqueue_raw(self, content: bytes, content_type: str, **kw: Any) -> None:
        self.enqueue(self.raw_response(content, content_type, **kw))

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._queue:
            return self._queue.pop(0)
        # default: empty v3 success envelope
        return self.envelope_response({})

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]


@pytest.fixture
def server() -> MockServer:
    return MockServer()


@pytest.fixture
def make_api(server):
    """Factory: API instance with the wire replaced by MockTransport.

    The constructor has no transport-injection parameter (and its signature
    must not change), so the private ``_client._transport`` is swapped. The
    ``VulnersApiTransport`` wrapper is kept in the chain: its set-cookie
    stripping is pinned behavior (and matters for close and redirect handling later).
    """
    created: list[VulnersApiBase] = []

    def _make(cls: type = vulners.VulnersApi, api_key: str = TEST_API_KEY) -> Any:
        api = cls(api_key)
        api._client._transport = VulnersApiTransport(httpx.MockTransport(server.handler))
        created.append(api)
        return api

    yield _make
    for api in created:
        api._client.close()


@pytest.fixture
def api(make_api):
    """VulnersApi("<synthetic key>") wired to the MockServer."""
    return make_api(vulners.VulnersApi)
