"""Reactive retry behaviour of the request loops (respx)."""

from __future__ import annotations

import httpx
import orjson
import pytest
import respx

import vulners._transport_client_async as _tca
import vulners._transport_client_sync as _tcs
from vulners._base_client import RequestSpec
from vulners._client import AsyncVulners, Vulners
from vulners._exceptions import APIConnectionError, APITimeoutError, InternalServerError

KEY = "SYNTHETIC-TEST-KEY"
SEARCH_URL = "https://vulners.com/api/v3/search/lucene/"


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch):
    # Collapse backoff waits so retries do not actually sleep. _retry_timeout now
    # lives in the split transport-client modules (sync + async mirrors).
    monkeypatch.setattr(_tcs, "_retry_timeout", lambda *a, **k: 0.0)
    monkeypatch.setattr(_tca, "_retry_timeout", lambda *a, **k: 0.0)


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


class TestProxyErrorRetry:
    @respx.mock
    def test_407_proxy_auth_not_retried(self):
        # A proxy that rejects the CONNECT with 407 will reject it identically on
        # retry, so the failure is terminal: one attempt, no retries. The raised
        # error names the proxy (credentials stripped) but keeps its type.
        route = respx.post(SEARCH_URL).mock(
            side_effect=httpx.ProxyError("407 Proxy Authentication Required")
        )
        with Vulners(KEY, proxy="http://user:secret@proxy.local:3128") as client:
            with pytest.raises(APIConnectionError) as excinfo:
                client.search.query("ssh")
        assert route.call_count == 1
        message = str(excinfo.value)
        assert "407" in message
        assert "(proxy http://proxy.local:3128)" in message
        assert "secret" not in message

    @respx.mock
    def test_non_407_proxy_error_still_retried(self):
        # Only 407 is terminal; other proxy errors stay retryable (idempotent GET).
        route = respx.post(SEARCH_URL).mock(side_effect=httpx.ProxyError("502 Bad Gateway"))
        with Vulners(KEY, proxy="http://proxy.local:3128") as client:
            with pytest.raises(APIConnectionError):
                client.search.query("ssh")
        assert route.call_count == 3

    @respx.mock
    async def test_407_proxy_auth_not_retried_async(self):
        route = respx.post(SEARCH_URL).mock(
            side_effect=httpx.ProxyError("407 Proxy Authentication Required")
        )
        async with AsyncVulners(KEY, proxy="http://proxy.local:3128") as client:
            with pytest.raises(APIConnectionError) as excinfo:
                await client.search.query("ssh")
        assert route.call_count == 1
        assert "(proxy http://proxy.local:3128)" in str(excinfo.value)
