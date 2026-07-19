"""Misc resource request-wire and parsing (respx)."""

from __future__ import annotations

import httpx
import orjson
import respx

from vulners._client import AsyncVulners, Vulners

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com"


def _v3(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": "OK", "data": payload}))


def _v4(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": payload}))


class TestMiscWire:
    @respx.mock
    def test_search_cpe_query_and_unwrap(self):
        route = respx.get(f"{BASE}/api/v4/search/cpe").mock(return_value=_v4([{"cpe": "x"}]))
        with Vulners(KEY) as client:
            out = client.misc.search_cpe("nginx", vendor="f5", size=10)
        assert out == [{"cpe": "x"}]
        params = route.calls.last.request.url.params
        assert params["product"] == "nginx"
        assert params["vendor"] == "f5"
        assert params["size"] == "10"

    @respx.mock
    def test_query_autocomplete_flattens(self):
        respx.post(f"{BASE}/api/v3/search/autocomplete/").mock(
            return_value=_v3({"suggestions": [["ssh", 1], ["sshd", 2]]})
        )
        with Vulners(KEY) as client:
            out = client.misc.query_autocomplete("ss")
        assert out == ["ssh", "sshd"]

    @respx.mock
    def test_get_suggestion_wire_and_unwrap(self):
        route = respx.post(f"{BASE}/api/v3/search/suggest/").mock(
            return_value=_v3({"suggest": [{"value": "a"}]})
        )
        with Vulners(KEY) as client:
            out = client.misc.get_suggestion("type")
        assert out == [{"value": "a"}]
        assert orjson.loads(route.calls.last.request.content) == {
            "fieldName": "type",
            "type": "distinct",
        }

    @respx.mock
    def test_web_application_rules(self):
        respx.get(f"{BASE}/api/v3/burp/rules/").mock(return_value=_v3({"rules": []}))
        with Vulners(KEY) as client:
            out = client.misc.get_web_application_rules()
        assert out == {"rules": []}


class TestMiscAsync:
    @respx.mock
    async def test_autocomplete_async(self):
        respx.post(f"{BASE}/api/v3/search/autocomplete/").mock(
            return_value=_v3({"suggestions": [["ssh", 1]]})
        )
        async with AsyncVulners(KEY) as client:
            assert await client.misc.query_autocomplete("ss") == ["ssh"]
