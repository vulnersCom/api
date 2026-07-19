"""STIX resource request-wire, unwrap and double-JSON decode (respx)."""

from __future__ import annotations

import httpx
import orjson
import respx

from vulners._client import AsyncVulners, Vulners

KEY = "SYNTHETIC-TEST-KEY"
URL = "https://vulners.com/api/v4/stix/bundle"


class TestStixWire:
    @respx.mock
    def test_bundle_object_result(self):
        route = respx.get(URL).mock(
            return_value=httpx.Response(200, content=orjson.dumps({"result": {"type": "bundle"}}))
        )
        with Vulners(KEY) as client:
            out = client.stix.make_bundle_by_id("CVE-2099-1", opencti_id="octi-1")
        assert out == {"type": "bundle"}
        params = route.calls.last.request.url.params
        assert params["id"] == "CVE-2099-1"
        assert params["opencti_id"] == "octi-1"

    @respx.mock
    def test_bundle_result_as_json_string_is_parsed(self):
        # The server sometimes double-encodes result as a JSON string.
        inner = orjson.dumps({"type": "bundle", "id": "b--1"}).decode()
        respx.get(URL).mock(
            return_value=httpx.Response(200, content=orjson.dumps({"result": inner}))
        )
        with Vulners(KEY) as client:
            out = client.stix.make_bundle_by_id("CVE-2099-1")
        assert out == {"type": "bundle", "id": "b--1"}

    @respx.mock
    def test_opencti_id_omitted_when_none(self):
        route = respx.get(URL).mock(
            return_value=httpx.Response(200, content=orjson.dumps({"result": {}}))
        )
        with Vulners(KEY) as client:
            client.stix.make_bundle_by_id("CVE-2099-1")
        assert "opencti_id" not in route.calls.last.request.url.params


class TestStixAsync:
    @respx.mock
    async def test_bundle_async_string_result(self):
        inner = orjson.dumps({"type": "bundle"}).decode()
        respx.get(URL).mock(
            return_value=httpx.Response(200, content=orjson.dumps({"result": inner}))
        )
        async with AsyncVulners(KEY) as client:
            assert await client.stix.make_bundle_by_id("CVE-1") == {"type": "bundle"}
