"""Client convenience config (proxy/verify/trust_env) and observation hooks.

Covers the constructor surface added to ``Vulners``/``AsyncVulners``: the
transport conveniences plumbed into the SDK-owned httpx client, their rejection
next to a bring-your-own ``http_client``, and the ``before_request`` /
``after_response`` / ``on_error`` hooks (sync client: plain callables; async
client: sync or async callables). Synthetic data throughout.
"""

from __future__ import annotations

import ssl

import httpcore
import httpx
import pytest
import respx

from vulners._client import AsyncVulners, Vulners
from vulners._exceptions import (
    APIConnectionError,
    APITimeoutError,
    InternalServerError,
)

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com"
LUCENE = f"{BASE}/api/v3/search/lucene/"


def _ok() -> httpx.Response:
    import orjson

    return httpx.Response(
        200, content=orjson.dumps({"result": "OK", "data": {"search": [], "total": 0}})
    )


# ---------------------------------------------------------------------------
# proxy / verify / trust_env plumbing
# ---------------------------------------------------------------------------


class TestTransportConveniences:
    def test_sync_proxy_reaches_inner_transport(self):
        with Vulners(KEY, proxy="http://proxy.local:3128") as client:
            assert client.config.proxy == "http://proxy.local:3128"
            inner = client._api._client._transport._transport
            assert isinstance(inner._pool, httpcore.HTTPProxy)

    async def test_async_proxy_reaches_inner_transport(self):
        async with AsyncVulners(KEY, proxy="http://proxy.local:3128") as client:
            inner = client._api._client._transport._transport
            assert isinstance(inner._pool, httpcore.AsyncHTTPProxy)

    def test_sync_verify_false_disables_tls_verification(self):
        with Vulners(KEY, verify=False) as client:
            inner = client._api._client._transport._transport
            assert inner._pool._ssl_context.verify_mode == ssl.CERT_NONE

    def test_sync_verify_ssl_context_is_used(self):
        context = ssl.create_default_context()
        with Vulners(KEY, verify=context) as client:
            inner = client._api._client._transport._transport
            assert inner._pool._ssl_context is context

    def test_sync_trust_env_false_propagates(self):
        with Vulners(KEY, trust_env=False) as client:
            assert client.config.trust_env is False
            assert client._api._client._trust_env is False

    async def test_async_trust_env_false_propagates(self):
        async with AsyncVulners(KEY, trust_env=False) as client:
            assert client._api._client._trust_env is False


# ---------------------------------------------------------------------------
# bring-your-own http_client conflicts
# ---------------------------------------------------------------------------


class TestByoConflicts:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"proxy": "http://proxy.local:3128"},
            {"verify": False},
            {"trust_env": False},
            {"before_request": lambda r: None},
            {"after_response": lambda r: None},
        ],
    )
    def test_sync_rejected_with_http_client(self, kwargs):
        http_client = httpx.Client()
        try:
            with pytest.raises(ValueError, match="http_client"):
                Vulners(KEY, http_client=http_client, **kwargs)
        finally:
            http_client.close()

    async def test_async_rejected_with_http_client(self):
        http_client = httpx.AsyncClient()
        try:
            with pytest.raises(ValueError, match="http_client"):
                AsyncVulners(KEY, http_client=http_client, verify=False)
        finally:
            await http_client.aclose()

    def test_on_error_allowed_with_http_client(self):
        # on_error runs in the SDK's request loop, not on the httpx client, so
        # it works with a bring-your-own client and must not be rejected.
        http_client = httpx.Client()
        client = Vulners(KEY, http_client=http_client, on_error=lambda e: None)
        client.close()
        http_client.close()


# ---------------------------------------------------------------------------
# sync client hooks
# ---------------------------------------------------------------------------


class TestSyncHooks:
    @respx.mock
    def test_before_request_and_after_response_fire(self):
        respx.post(LUCENE).mock(return_value=_ok())
        requests: list[httpx.Request] = []
        responses: list[httpx.Response] = []
        with Vulners(
            KEY, before_request=requests.append, after_response=responses.append
        ) as client:
            client.search.query("ssh")
        assert requests and requests[0].url.path == "/api/v3/search/lucene/"
        assert responses and responses[0].status_code == 200

    @respx.mock
    def test_hook_lists_fire_in_order(self):
        respx.post(LUCENE).mock(return_value=_ok())
        seen: list[str] = []
        with Vulners(
            KEY,
            before_request=[lambda r: seen.append("first"), lambda r: seen.append("second")],
        ) as client:
            client.search.query("ssh")
        assert seen == ["first", "second"]

    def test_async_hook_on_sync_client_rejected(self):
        async def hook(request):  # pragma: no cover - never invoked
            pass

        with pytest.raises(TypeError, match="async"):
            Vulners(KEY, before_request=hook)

    @respx.mock
    def test_on_error_receives_status_error(self):
        respx.post(LUCENE).mock(return_value=httpx.Response(500, text="boom"))
        errors: list[Exception] = []
        with Vulners(KEY, max_retries=0, on_error=errors.append) as client:
            with pytest.raises(InternalServerError) as excinfo:
                client.search.query("ssh")
        assert errors == [excinfo.value]

    @respx.mock
    def test_on_error_receives_connection_error(self):
        respx.post(LUCENE).mock(side_effect=httpx.ConnectError("refused"))
        errors: list[Exception] = []
        with Vulners(KEY, max_retries=0, on_error=errors.append) as client:
            with pytest.raises(APIConnectionError) as excinfo:
                client.search.query("ssh")
        assert errors == [excinfo.value]

    @respx.mock
    def test_on_error_receives_timeout_error(self):
        respx.post(LUCENE).mock(side_effect=httpx.ReadTimeout("timed out"))
        errors: list[Exception] = []
        with Vulners(KEY, max_retries=0, on_error=errors.append) as client:
            with pytest.raises(APITimeoutError) as excinfo:
                client.search.query("ssh")
        assert errors == [excinfo.value]

    @respx.mock
    def test_on_error_hook_exception_propagates(self):
        respx.post(LUCENE).mock(return_value=httpx.Response(500, text="boom"))

        def hook(error: Exception) -> None:
            raise RuntimeError("hook exploded")

        with Vulners(KEY, max_retries=0, on_error=hook) as client:
            with pytest.raises(RuntimeError, match="hook exploded"):
                client.search.query("ssh")


# ---------------------------------------------------------------------------
# async client hooks (sync and async callables both work)
# ---------------------------------------------------------------------------


class TestAsyncHooks:
    @respx.mock
    async def test_sync_and_async_hooks_both_fire(self):
        respx.post(LUCENE).mock(return_value=_ok())
        seen: list[str] = []

        async def async_hook(request: httpx.Request) -> None:
            seen.append("async")

        async with AsyncVulners(
            KEY,
            before_request=[async_hook, lambda r: seen.append("sync")],
            after_response=lambda r: seen.append("response"),
        ) as client:
            await client.search.query("ssh")
        assert seen == ["async", "sync", "response"]

    @respx.mock
    async def test_on_error_async_hook_receives_status_error(self):
        respx.post(LUCENE).mock(return_value=httpx.Response(500, text="boom"))
        errors: list[Exception] = []

        async def hook(error: Exception) -> None:
            errors.append(error)

        async with AsyncVulners(KEY, max_retries=0, on_error=hook) as client:
            with pytest.raises(InternalServerError) as excinfo:
                await client.search.query("ssh")
        assert errors == [excinfo.value]

    @respx.mock
    async def test_on_error_connection_and_timeout(self):
        errors: list[Exception] = []
        respx.post(LUCENE).mock(side_effect=httpx.ConnectError("refused"))
        async with AsyncVulners(KEY, max_retries=0, on_error=errors.append) as client:
            with pytest.raises(APIConnectionError):
                await client.search.query("ssh")
        respx.post(LUCENE).mock(side_effect=httpx.ReadTimeout("timed out"))
        async with AsyncVulners(KEY, max_retries=0, on_error=errors.append) as client:
            with pytest.raises(APITimeoutError):
                await client.search.query("ssh")
        assert [type(e) for e in errors] == [APIConnectionError, APITimeoutError]
