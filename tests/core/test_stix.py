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
    def test_bundle_string_with_bigint_and_infinity_parsed_leniently(self):
        # orjson rejects >64-bit ints and Infinity; the second parse falls back
        # to the stdlib decoder so such CVE-data edges still decode.
        import json

        inner = json.dumps({"big": 2**80, "inf": float("inf")})
        respx.get(URL).mock(
            return_value=httpx.Response(200, content=orjson.dumps({"result": inner}))
        )
        with Vulners(KEY) as client:
            out = client.stix.make_bundle_by_id("CVE-2099-1")
        assert out["big"] == 2**80
        assert out["inf"] == float("inf")

    @respx.mock
    def test_bundle_non_json_string_result_returned_as_is(self):
        respx.get(URL).mock(
            return_value=httpx.Response(200, content=orjson.dumps({"result": "not-json"}))
        )
        with Vulners(KEY) as client:
            assert client.stix.make_bundle_by_id("CVE-2099-1") == "not-json"

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


class TestStixBundleAlias:
    @respx.mock
    def test_bundle_delegates_to_make_bundle_by_id(self):
        route = respx.get(URL).mock(
            return_value=httpx.Response(200, content=orjson.dumps({"result": {"type": "bundle"}}))
        )
        with Vulners(KEY) as client:
            assert client.stix.bundle("CVE-2099-1", opencti_id="octi-2") == {"type": "bundle"}
        params = route.calls.last.request.url.params
        assert params["id"] == "CVE-2099-1"
        assert params["opencti_id"] == "octi-2"

    @respx.mock
    async def test_bundle_alias_async(self):
        route = respx.get(URL).mock(
            return_value=httpx.Response(200, content=orjson.dumps({"result": {"type": "bundle"}}))
        )
        async with AsyncVulners(KEY) as client:
            assert await client.stix.bundle("CVE-2099-2") == {"type": "bundle"}
        assert route.calls.last.request.url.params["id"] == "CVE-2099-2"
