"""Escape hatches: client.get/post/put/delete against an arbitrary API path."""

from __future__ import annotations

import httpx
import orjson
import respx

from vulners._client import AsyncVulners, Vulners

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com"


def _json(payload: object) -> httpx.Response:
    return httpx.Response(
        200, content=orjson.dumps(payload), headers={"content-type": "application/json"}
    )


class TestSyncEscapeHatches:
    @respx.mock
    def test_get_with_params(self):
        route = respx.get(f"{BASE}/api/v3/version/").mock(
            return_value=_json({"result": "OK", "data": {"v": 3}})
        )
        with Vulners(KEY) as v:
            out = v.get("/api/v3/version/", params={"a": "b"})
        assert out == {"result": "OK", "data": {"v": 3}}  # returned as-is (no envelope unwrap)
        assert route.calls.last.request.url.params["a"] == "b"
        assert route.calls.last.request.headers["x-api-key"] == KEY

    @respx.mock
    def test_post_json_body(self):
        route = respx.post(f"{BASE}/custom/echo").mock(return_value=_json({"ok": True}))
        with Vulners(KEY) as v:
            out = v.post("/custom/echo", json={"q": "test"}, params={"x": "1"})
        assert out == {"ok": True}
        req = route.calls.last.request
        assert orjson.loads(req.content) == {"q": "test"}
        assert req.url.params["x"] == "1"

    @respx.mock
    def test_put_json_body(self):
        route = respx.put(f"{BASE}/custom/item").mock(return_value=_json({"updated": 1}))
        with Vulners(KEY) as v:
            out = v.put("/custom/item", json={"name": "x"})
        assert out == {"updated": 1}
        assert orjson.loads(route.calls.last.request.content) == {"name": "x"}

    @respx.mock
    def test_delete_with_params(self):
        route = respx.delete(f"{BASE}/custom/item").mock(return_value=_json({"deleted": 1}))
        with Vulners(KEY) as v:
            out = v.delete("/custom/item", params={"id": "42"})
        assert out == {"deleted": 1}
        assert route.calls.last.request.url.params["id"] == "42"


class TestAsyncEscapeHatches:
    @respx.mock
    async def test_get(self):
        respx.get(f"{BASE}/api/v3/version/").mock(
            return_value=_json({"result": "OK", "data": {"v": 4}})
        )
        async with AsyncVulners(KEY) as v:
            out = await v.get("/api/v3/version/", params={"a": "b"})
        assert out == {"result": "OK", "data": {"v": 4}}

    @respx.mock
    async def test_post(self):
        route = respx.post(f"{BASE}/custom/echo").mock(return_value=_json({"ok": True}))
        async with AsyncVulners(KEY) as v:
            out = await v.post("/custom/echo", json={"q": "t"})
        assert out == {"ok": True}
        assert orjson.loads(route.calls.last.request.content) == {"q": "t"}

    @respx.mock
    async def test_put(self):
        respx.put(f"{BASE}/custom/item").mock(return_value=_json({"updated": 1}))
        async with AsyncVulners(KEY) as v:
            out = await v.put("/custom/item", json={"name": "x"})
        assert out == {"updated": 1}

    @respx.mock
    async def test_delete(self):
        route = respx.delete(f"{BASE}/custom/item").mock(return_value=_json({"deleted": 1}))
        async with AsyncVulners(KEY) as v:
            out = await v.delete("/custom/item", params={"id": "7"})
        assert out == {"deleted": 1}
        assert route.calls.last.request.url.params["id"] == "7"
