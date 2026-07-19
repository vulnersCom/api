"""Reactive retry behaviour of the request loops (respx)."""

from __future__ import annotations

import httpx
import orjson
import pytest
import respx

import vulners._base_client as bc
from vulners._base_client import RequestSpec
from vulners._client import Vulners
from vulners._exceptions import APIConnectionError, APITimeoutError, InternalServerError

KEY = "SYNTHETIC-TEST-KEY"
SEARCH_URL = "https://vulners.com/api/v3/search/lucene/"


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch):
    # Collapse backoff waits so retries do not actually sleep.
    monkeypatch.setattr(bc, "_retry_timeout", lambda *a, **k: 0.0)


def _ok() -> httpx.Response:
    return httpx.Response(
        200, content=orjson.dumps({"result": "OK", "data": {"search": [], "total": 0}})
    )


class TestStatusRetry:
    @respx.mock
    def test_502_then_success(self):
        route = respx.post(SEARCH_URL).mock(
            side_effect=[httpx.Response(502, text="bad gateway"), _ok()]
        )
        with Vulners(KEY) as client:
            page = client.search.query("ssh")
        assert route.call_count == 2
        assert page.total == 0

    @respx.mock
    def test_429_with_numeric_retry_after_is_honored(self):
        route = respx.post(SEARCH_URL).mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0"}, json={"error": "slow"}),
                _ok(),
            ]
        )
        with Vulners(KEY) as client:
            client.search.query("ssh")
        assert route.call_count == 2

    @respx.mock
    def test_429_with_http_date_retry_after_is_honored(self):
        route = respx.post(SEARCH_URL).mock(
            side_effect=[
                httpx.Response(
                    429,
                    headers={"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"},
                    json={"error": "slow"},
                ),
                _ok(),
            ]
        )
        with Vulners(KEY) as client:
            client.search.query("ssh")
        assert route.call_count == 2

    @respx.mock
    def test_exhausts_retries_then_raises(self):
        route = respx.post(SEARCH_URL).mock(return_value=httpx.Response(500, text="boom"))
        with Vulners(KEY) as client:
            with pytest.raises(InternalServerError):
                client.search.query("ssh")
        # default max_retries=2 -> 1 initial + 2 retries
        assert route.call_count == 3


class TestTimeoutRetry:
    @respx.mock
    def test_read_timeout_retried_on_idempotent(self):
        # search.query is marked idempotent -> a read timeout is retried.
        route = respx.post(SEARCH_URL).mock(side_effect=httpx.ReadTimeout("timed out"))
        with Vulners(KEY) as client:
            with pytest.raises(APITimeoutError):
                client.search.query("ssh")
        assert route.call_count == 3

    @respx.mock
    def test_read_timeout_not_retried_on_non_idempotent(self):
        url = "https://vulners.com/api/v3/non-idempotent/"
        route = respx.post(url).mock(side_effect=httpx.ReadTimeout("timed out"))
        spec = RequestSpec("POST", "/api/v3/non-idempotent/", body_mode="json")
        with Vulners(KEY) as client:
            with pytest.raises(APITimeoutError):
                client._api.request(spec, body={})
        assert route.call_count == 1

    @respx.mock
    def test_connect_error_retried_even_on_non_idempotent(self):
        url = "https://vulners.com/api/v3/non-idempotent/"
        route = respx.post(url).mock(side_effect=httpx.ConnectError("refused"))
        spec = RequestSpec("POST", "/api/v3/non-idempotent/", body_mode="json")
        with Vulners(KEY) as client:
            with pytest.raises(APIConnectionError):
                client._api.request(spec, body={})
        # connection never delivered the request -> safe to retry
        assert route.call_count == 3
