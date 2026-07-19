"""Client lifecycle: context managers, double-close, injected client, options."""

from __future__ import annotations

import httpx

from vulners._client import AsyncVulners, Vulners

KEY = "SYNTHETIC-TEST-KEY"


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
