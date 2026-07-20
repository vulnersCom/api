"""v4 subscriptions resource request-wire and parsing (respx).

The v4 CRUD is the primary ``client.subscriptions`` resource;
``client.subscriptions_v4`` remains a deprecated alias of the same instance and
the v3 email subscriptions moved to ``client.subscriptions_email``.
"""

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


class TestSubscriptionsRename:
    def test_subscriptions_v4_is_alias_of_subscriptions(self):
        with Vulners(KEY) as client:
            assert client.subscriptions_v4 is client.subscriptions

    def test_email_resource_moved(self):
        from vulners._resources._sync.subscriptions import Subscriptions
        from vulners._resources._sync.subscriptions_v4 import SubscriptionsV4

        with Vulners(KEY) as client:
            assert isinstance(client.subscriptions, SubscriptionsV4)
            assert isinstance(client.subscriptions_email, Subscriptions)

    async def test_async_alias_and_email_resource(self):
        from vulners._resources._async.subscriptions import AsyncSubscriptions
        from vulners._resources._async.subscriptions_v4 import AsyncSubscriptionsV4

        async with AsyncVulners(KEY) as client:
            assert client.subscriptions_v4 is client.subscriptions
            assert isinstance(client.subscriptions, AsyncSubscriptionsV4)
            assert isinstance(client.subscriptions_email, AsyncSubscriptions)


class TestSubscriptionsV4Wire:
    @respx.mock
    def test_list_unwraps_result(self):
        respx.get(f"{BASE}/list/").mock(return_value=_v4([{"id": "s1"}]))
        with Vulners(KEY) as client:
            assert client.subscriptions.list() == [{"id": "s1"}]

    @respx.mock
    def test_get_list_is_list_alias(self):
        respx.get(f"{BASE}/list/").mock(return_value=_v4([{"id": "s1"}]))
        with Vulners(KEY) as client:
            assert client.subscriptions.get_list() == [{"id": "s1"}]

    @respx.mock
    def test_get_sends_subscription_id_query(self):
        route = respx.get(f"{BASE}/get/").mock(return_value=_v4({"id": "s1"}))
        with Vulners(KEY) as client:
            client.subscriptions.get("s2")
        assert route.calls.last.request.url.params["subscription_id"] == "s2"

    @respx.mock
    def test_get_accepts_subscription_id_keyword(self):
        route = respx.get(f"{BASE}/get/").mock(return_value=_v4({"id": "s1"}))
        with Vulners(KEY) as client:
            client.subscriptions.get(subscription_id="s3")
        assert route.calls.last.request.url.params["subscription_id"] == "s3"

    def test_get_requires_exactly_one_id(self):
        with Vulners(KEY) as client:
            with pytest.raises(TypeError):
                client.subscriptions.get()
            with pytest.raises(TypeError):
                client.subscriptions.get("s1", subscription_id="s1")

    @respx.mock
    def test_create_sends_full_body_with_defaults(self):
        route = respx.post(f"{BASE}/create/").mock(return_value=_v4({"id": "s1"}))
        with Vulners(KEY) as client:
            client.subscriptions.create(
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
    def test_create_with_typed_query_and_delivery(self):
        from vulners._types.subscriptions import (
            SubscriptionDeliveryWebhook,
            SubscriptionQueryLucene,
        )

        route = respx.post(f"{BASE}/create/").mock(return_value=_v4({"id": "s1"}))
        query = SubscriptionQueryLucene(type="query", query="type:cve")
        delivery = SubscriptionDeliveryWebhook(
            type="webhook", address="https://example.com/hook", crontab="0 * * * *"
        )
        with Vulners(KEY) as client:
            client.subscriptions.create(
                name="n", query=query, delivery=delivery, bulletin_fields=["title"]
            )
        body = orjson.loads(route.calls.last.request.content)
        assert body["query"] == {"type": "query", "query": "type:cve"}
        assert body["delivery"]["type"] == "webhook"
        assert body["bulletin_fields"] == ["title"]

    @respx.mock
    def test_update_partial_sends_only_given_fields(self):
        # Partial-update contract: the body carries the id plus exactly the
        # fields that were passed — nothing else.
        route = respx.put(f"{BASE}/update/").mock(return_value=_v4({"id": "s1"}))
        with Vulners(KEY) as client:
            client.subscriptions.update("s1", name="x")
        assert orjson.loads(route.calls.last.request.content) == {"id": "s1", "name": "x"}

    @respx.mock
    def test_update_all_fields(self):
        route = respx.put(f"{BASE}/update/").mock(return_value=_v4({"id": "s1"}))
        with Vulners(KEY) as client:
            client.subscriptions.update(
                "s1",
                name="n",
                query={"type": "software"},
                delivery={"type": "webhook"},
                license_id="lic-1",
                bulletin_fields=["title"],
                is_active=False,
                timestamp_source="published",
                send_empty_result=True,
            )
        assert orjson.loads(route.calls.last.request.content) == {
            "id": "s1",
            "name": "n",
            "query": {"type": "software"},
            "delivery": {"type": "webhook"},
            "licenseId": "lic-1",
            "bulletin_fields": ["title"],
            "is_active": False,
            "timestamp_source": "published",
            "send_empty_result": True,
        }

    @respx.mock
    def test_delete_is_delete_with_id_query(self):
        route = respx.delete(f"{BASE}/delete/").mock(return_value=_v4({"ok": True}))
        with Vulners(KEY) as client:
            client.subscriptions.delete("s1")
        assert route.calls.last.request.url.params["id"] == "s1"


class TestSubscriptionsV4Async:
    @respx.mock
    async def test_create_async(self):
        respx.post(f"{BASE}/create/").mock(return_value=_v4({"id": "s9"}))
        async with AsyncVulners(KEY) as client:
            out = await client.subscriptions.create(name="n", query={}, delivery={})
        assert out == {"id": "s9"}

    @respx.mock
    async def test_update_partial_async(self):
        route = respx.put(f"{BASE}/update/").mock(return_value=_v4({"id": "s1"}))
        async with AsyncVulners(KEY) as client:
            await client.subscriptions.update("s1", is_active=False)
        assert orjson.loads(route.calls.last.request.content) == {
            "id": "s1",
            "is_active": False,
        }
