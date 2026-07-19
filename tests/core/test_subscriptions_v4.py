"""v4 subscriptions resource request-wire and parsing (respx)."""

from __future__ import annotations

import httpx
import orjson
import pytest
import respx

from vulners._client import AsyncVulners, Vulners

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com/api/v4/subscriptions"

DEFAULT_FIELDS = [
    "title",
    "short_description",
    "type",
    "href",
    "published",
    "modified",
    "ai_score",
]


def _v4(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": payload}))


class TestSubscriptionsV4Wire:
    @respx.mock
    def test_get_list_unwraps_result(self):
        respx.get(f"{BASE}/list/").mock(return_value=_v4([{"id": "s1"}]))
        with Vulners(KEY) as client:
            assert client.subscriptions_v4.get_list() == [{"id": "s1"}]

    @respx.mock
    def test_get_sends_subscription_id_query(self):
        route = respx.get(f"{BASE}/get/").mock(return_value=_v4({"id": "s1"}))
        with Vulners(KEY) as client:
            client.subscriptions_v4.get("s2")
        assert route.calls.last.request.url.params["subscription_id"] == "s2"

    def test_get_requires_id(self):
        with Vulners(KEY) as client:
            with pytest.raises(TypeError):
                client.subscriptions_v4.get()

    @respx.mock
    def test_create_sends_full_body_with_defaults(self):
        route = respx.post(f"{BASE}/create/").mock(return_value=_v4({"id": "s1"}))
        with Vulners(KEY) as client:
            client.subscriptions_v4.create(
                name="n", query={"type": "software"}, delivery={"type": "webhook"}
            )
        assert orjson.loads(route.calls.last.request.content) == {
            "name": "n",
            "query": {"type": "software"},
            "delivery": {"type": "webhook"},
            "licenseId": None,
            "bulletin_fields": DEFAULT_FIELDS,
            "is_active": True,
            "timestamp_source": "modified",
            "send_empty_result": False,
        }

    @respx.mock
    def test_update_is_put_with_id(self):
        route = respx.put(f"{BASE}/update/").mock(return_value=_v4({"id": "s1"}))
        with Vulners(KEY) as client:
            client.subscriptions_v4.update(
                "s1",
                name="n",
                query={"type": "software"},
                delivery={"type": "webhook"},
                license_id="lic-1",
                is_active=False,
            )
        body = orjson.loads(route.calls.last.request.content)
        assert body["id"] == "s1"
        assert body["licenseId"] == "lic-1"
        assert body["is_active"] is False

    @respx.mock
    def test_delete_is_delete_with_id_query(self):
        route = respx.delete(f"{BASE}/delete/").mock(return_value=_v4({"ok": True}))
        with Vulners(KEY) as client:
            client.subscriptions_v4.delete("s1")
        assert route.calls.last.request.url.params["id"] == "s1"


class TestSubscriptionsV4Async:
    @respx.mock
    async def test_create_async(self):
        respx.post(f"{BASE}/create/").mock(return_value=_v4({"id": "s9"}))
        async with AsyncVulners(KEY) as client:
            out = await client.subscriptions_v4.create(name="n", query={}, delivery={})
        assert out == {"id": "s9"}
