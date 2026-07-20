"""v3 subscriptions resource request-wire and parsing (respx)."""

from __future__ import annotations

import httpx
import orjson
import respx

from vulners._client import AsyncVulners, Vulners

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com/api/v3/subscriptions"


def _v3(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": "OK", "data": payload}))


class TestSubscriptionsWire:
    @respx.mock
    def test_list_unwraps_and_no_key_in_query(self):
        route = respx.get(f"{BASE}/listEmailSubscriptions/").mock(
            return_value=_v3({"subscriptions": [{"id": "s1"}]})
        )
        with Vulners(KEY) as client:
            out = client.subscriptions_email.list()
        assert out == [{"id": "s1"}]
        assert "apiKey" not in route.calls.last.request.url.params

    @respx.mock
    def test_add_echoes_key_in_body(self):
        route = respx.post(f"{BASE}/addEmailSubscription/").mock(return_value=_v3({"id": "s1"}))
        with Vulners(KEY) as client:
            client.subscriptions_email.add(query="ssh", email="a@b.c", crontab="0 0 * * *")
        assert orjson.loads(route.calls.last.request.content) == {
            "query": "ssh",
            "email": "a@b.c",
            "format": "html",
            "query_type": "lucene",
            "crontab": "0 0 * * *",
            "apiKey": KEY,
        }

    @respx.mock
    def test_edit_sends_only_given_optionals(self):
        route = respx.post(f"{BASE}/editEmailSubscription/").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.subscriptions_email.edit("s1", active="yes")
        assert orjson.loads(route.calls.last.request.content) == {
            "subscriptionid": "s1",
            "active": "yes",
            "apiKey": KEY,
        }

    @respx.mock
    def test_delete_wire(self):
        route = respx.post(f"{BASE}/removeEmailSubscription/").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.subscriptions_email.delete("s1")
        assert orjson.loads(route.calls.last.request.content) == {
            "subscriptionid": "s1",
            "apiKey": KEY,
        }


class TestSubscriptionsOwnerKey:
    """Passing ``api_key`` names a different subscription owner in the body while
    the client's own key stays in the ``X-Api-Key`` header."""

    OWNER = "OWNER-KEY-XYZ"

    @respx.mock
    def test_add_owner_key_in_body_header_unchanged(self):
        route = respx.post(f"{BASE}/addEmailSubscription/").mock(return_value=_v3({"id": "s1"}))
        with Vulners(KEY) as client:
            client.subscriptions_email.add(query="ssh", email="a@b.c", api_key=self.OWNER)
        req = route.calls.last.request
        assert orjson.loads(req.content)["apiKey"] == self.OWNER
        assert req.headers["X-Api-Key"] == KEY

    @respx.mock
    def test_edit_and_delete_owner_key(self):
        edit = respx.post(f"{BASE}/editEmailSubscription/").mock(return_value=_v3({}))
        dele = respx.post(f"{BASE}/removeEmailSubscription/").mock(return_value=_v3({}))
        with Vulners(KEY) as client:
            client.subscriptions_email.edit("s1", active="no", api_key=self.OWNER)
            client.subscriptions_email.delete("s1", api_key=self.OWNER)
        assert orjson.loads(edit.calls.last.request.content)["apiKey"] == self.OWNER
        assert orjson.loads(dele.calls.last.request.content)["apiKey"] == self.OWNER


class TestSubscriptionsAsync:
    @respx.mock
    async def test_list_async(self):
        respx.get(f"{BASE}/listEmailSubscriptions/").mock(return_value=_v3({"subscriptions": []}))
        async with AsyncVulners(KEY) as client:
            assert await client.subscriptions_email.list() == []
