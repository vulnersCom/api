"""Client lifecycle: context managers, double-close, injected client, options."""

from __future__ import annotations

import httpx

from vulners._client import AsyncVulners, Vulners
from vulners._transport import AsyncVulnersTransport, VulnersTransport

KEY = "SYNTHETIC-TEST-KEY"


def _redirect_recorder(records: list[httpx.Request]):
    """A handler that 302s the origin hop to a cross-origin host, then 200s."""

    def handler(request: httpx.Request) -> httpx.Response:
        records.append(request)
        if request.url.host == "vulners.com":
            return httpx.Response(302, headers={"location": "https://evil.example/steal"})
        return httpx.Response(200, json={"result": "OK", "data": {}})

    return handler


class TestSyncLifecycle:
    def test_context_manager_closes(self):
        with Vulners(KEY) as client:
            assert not client.is_closed
        assert client.is_closed

    def test_double_close_is_safe(self):
        client = Vulners(KEY)
        client.close()
        client.close()  # no error
        assert client.is_closed

    def test_injected_client_not_closed(self):
        http_client = httpx.Client()
        client = Vulners(KEY, http_client=http_client)
        client.close()
        assert not http_client.is_closed
        http_client.close()

    def test_with_options_shares_pool_and_overrides(self):
        client = Vulners(KEY, max_retries=2)
        clone = client.with_options(max_retries=7)
        assert clone.config.max_retries == 7
        assert client.config.max_retries == 2
        # the clone shares the same underlying httpx client (connection pool)
        assert clone._api._client is client._api._client
        # closing the clone must not close the shared, borrowed client
        clone.close()
        assert not client.is_closed
        client.close()

    def test_with_options_shares_pacing_buckets(self):
        # The clone must share the parent's rate-limit buckets, or per-variant
        # pacing resets and combined throughput can exceed the account limit.
        client = Vulners(KEY)
        clone = client.with_options(timeout=5.0)
        assert clone._api._buckets is client._api._buckets
        client.close()

    def test_injected_client_transport_is_guarded(self):
        http_client = httpx.Client()
        client = Vulners(KEY, http_client=http_client)
        # The BYO transport is wrapped so the credential guard still runs.
        assert isinstance(http_client._transport, VulnersTransport)
        client.close()
        http_client.close()

    def test_injected_client_strips_key_cross_origin(self):
        records: list[httpx.Request] = []
        http_client = httpx.Client(
            transport=httpx.MockTransport(_redirect_recorder(records)),
            follow_redirects=True,
        )
        client = Vulners(KEY, base_url="https://vulners.com", http_client=http_client)
        client.misc.get_web_application_rules()
        client.close()
        http_client.close()
        # origin hop carries the key; the cross-origin redirect hop must not.
        assert records[0].url.host == "vulners.com"
        assert records[0].headers.get("x-api-key") == KEY
        assert records[1].url.host == "evil.example"
        assert "x-api-key" not in records[1].headers

    def test_key_never_leaks_in_repr(self):
        client = Vulners(KEY)
        assert KEY not in repr(client.config)
        client.close()


class TestAsyncLifecycle:
    async def test_context_manager_closes(self):
        async with AsyncVulners(KEY) as client:
            assert not client.is_closed
        assert client.is_closed

    async def test_double_close_is_safe(self):
        client = AsyncVulners(KEY)
        await client.aclose()
        await client.aclose()
        assert client.is_closed

    async def test_injected_client_not_closed(self):
        http_client = httpx.AsyncClient()
        client = AsyncVulners(KEY, http_client=http_client)
        await client.aclose()
        assert not http_client.is_closed
        await http_client.aclose()

    async def test_with_options_shares_pacing_buckets(self):
        client = AsyncVulners(KEY)
        clone = client.with_options(timeout=5.0)
        assert clone._api._buckets is client._api._buckets
        await client.aclose()

    async def test_injected_client_transport_is_guarded(self):
        http_client = httpx.AsyncClient()
        client = AsyncVulners(KEY, http_client=http_client)
        assert isinstance(http_client._transport, AsyncVulnersTransport)
        await client.aclose()
        await http_client.aclose()

    async def test_injected_client_strips_key_cross_origin(self):
        records: list[httpx.Request] = []
        http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(_redirect_recorder(records)),
            follow_redirects=True,
        )
        client = AsyncVulners(KEY, base_url="https://vulners.com", http_client=http_client)
        await client.misc.get_web_application_rules()
        await client.aclose()
        await http_client.aclose()
        assert records[0].headers.get("x-api-key") == KEY
        assert records[1].url.host == "evil.example"
        assert "x-api-key" not in records[1].headers
