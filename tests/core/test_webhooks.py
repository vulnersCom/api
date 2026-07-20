"""Webhooks resource request-wire and parsing (respx)."""

from __future__ import annotations

import httpx
import orjson
import respx

from vulners._client import AsyncVulners, Vulners

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com/api/v3/subscriptions"


def _v3(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": "OK", "data": payload}))


class TestWebhooksWire:
    @respx.mock
    def test_list_unwraps_and_no_key_in_query(self):
        route = respx.get(f"{BASE}/listWebhookSubscriptions/").mock(
            return_value=_v3({"subscriptions": [{"id": "w1"}]})
        )
        with Vulners(KEY) as client:
            out = client.webhooks.list()
        assert out == [{"id": "w1"}]
        assert "apiKey" not in route.calls.last.request.url.params

    @respx.mock
    def test_add_echoes_key_in_body(self):
        route = respx.post(f"{BASE}/addWebhookSubscription/").mock(return_value=_v3({"id": "w1"}))
        with Vulners(KEY) as client:
            client.webhooks.add("ssh")
        assert orjson.loads(route.calls.last.request.content) == {"query": "ssh", "apiKey": KEY}

    @respx.mock
    def test_enable_maps_bool_to_string(self):
        route = respx.post(f"{BASE}/editWebhookSubscription/").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.webhooks.enable("w1", False)
        assert orjson.loads(route.calls.last.request.content) == {
            "subscriptionid": "w1",
            "active": "false",
            "apiKey": KEY,
        }

    @respx.mock
    def test_read_requires_key_in_query(self):
        route = respx.get(f"{BASE}/webhook").mock(return_value=_v3({"payloads": []}))
        with Vulners(KEY) as client:
            out = client.webhooks.read("w1", newest_only=False)
        assert out == {"payloads": []}
        params = route.calls.last.request.url.params
        assert params["subscriptionid"] == "w1"
        assert params["newest_only"] == "false"
        assert params["apiKey"] == KEY

    @respx.mock
    def test_delete_wire(self):
        route = respx.post(f"{BASE}/removeWebhookSubscription/").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.webhooks.delete("w1")
        assert orjson.loads(route.calls.last.request.content) == {
            "subscriptionid": "w1",
            "apiKey": KEY,
        }


class TestWebhooksAsync:
    @respx.mock
    async def test_read_async(self):
        route = respx.get(f"{BASE}/webhook").mock(return_value=_v3({"payloads": [1]}))
        async with AsyncVulners(KEY) as client:
            out = await client.webhooks.read("w1")
        assert out == {"payloads": [1]}
        assert route.calls.last.request.url.params["apiKey"] == KEY


class TestWebhooksAliases:
    @respx.mock
    def test_create_delegates_to_add(self):
        route = respx.post(f"{BASE}/addWebhookSubscription/").mock(return_value=_v3({"id": "w2"}))
        with Vulners(KEY) as client:
            assert client.webhooks.create("ssh") == {"id": "w2"}
        assert orjson.loads(route.calls.last.request.content) == {"query": "ssh", "apiKey": KEY}

    @respx.mock
    def test_set_enabled_delegates_to_enable(self):
        route = respx.post(f"{BASE}/editWebhookSubscription/").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.webhooks.set_enabled("w1", True)
        assert orjson.loads(route.calls.last.request.content)["active"] == "true"

    @respx.mock
    async def test_async_aliases(self):
        add = respx.post(f"{BASE}/addWebhookSubscription/").mock(return_value=_v3({"id": "w3"}))
        edit = respx.post(f"{BASE}/editWebhookSubscription/").mock(return_value=_v3({}))
        async with AsyncVulners(KEY) as client:
            assert await client.webhooks.create("nginx") == {"id": "w3"}
            await client.webhooks.set_enabled("w3", False)
        assert orjson.loads(add.calls.last.request.content)["query"] == "nginx"
        assert orjson.loads(edit.calls.last.request.content)["active"] == "false"
