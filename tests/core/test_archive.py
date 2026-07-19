"""Archive resource request-wire, gzip decode and parsing (respx)."""

from __future__ import annotations

import gzip
from datetime import datetime, timezone

import httpx
import orjson
import respx

from vulners._client import AsyncVulners, Vulners

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com"


def _gzip_json(payload: object) -> httpx.Response:
    body = gzip.compress(orjson.dumps(payload))
    return httpx.Response(
        200, content=body, headers={"content-type": "application/x-gzip-compressed"}
    )


class TestArchiveWire:
    @respx.mock
    def test_fetch_collection_query_and_gzip_parse(self):
        route = respx.get(f"{BASE}/api/v4/archive/collection").mock(
            return_value=_gzip_json([{"id": "CVE-1"}])
        )
        with Vulners(KEY) as client:
            out = client.archive.fetch_collection("cve")
        assert out == [{"id": "CVE-1"}]
        assert route.calls.last.request.url.params["type"] == "cve"

    @respx.mock
    def test_fetch_collection_update_sends_after(self):
        route = respx.get(f"{BASE}/api/v4/archive/collection-update").mock(
            return_value=_gzip_json([])
        )
        after = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        with Vulners(KEY) as client:
            client.archive.fetch_collection_update("cve", after)
        params = route.calls.last.request.url.params
        assert params["type"] == "cve"
        assert params["after"] == after.isoformat()

    @respx.mock
    def test_get_collection_date_range(self):
        route = respx.get(f"{BASE}/api/v3/archive/collection/").mock(return_value=_gzip_json({}))
        with Vulners(KEY) as client:
            client.archive.get_collection("cve", datefrom="2020-01-01")
        params = route.calls.last.request.url.params
        assert params["type"] == "cve"
        assert params["datefrom"] == "2020-01-01"
        assert params["dateto"] == "2199-01-01"

    @respx.mock
    def test_get_distributive_extracts_source(self):
        respx.get(f"{BASE}/api/v3/archive/distributive/").mock(
            return_value=httpx.Response(
                200, content=orjson.dumps({"result": "OK", "data": [{"_source": {"id": "A"}}]})
            )
        )
        with Vulners(KEY) as client:
            out = client.archive.get_distributive("ubuntu", "22.04")
        assert out == [{"id": "A"}]

    @respx.mock
    def test_getsploit_returns_decompressed_bytes(self):
        respx.get(f"{BASE}/api/v3/archive/getsploit/").mock(
            return_value=httpx.Response(
                200,
                content=gzip.compress(b"raw-exploit-db"),
                headers={"content-type": "application/x-gzip-compressed"},
            )
        )
        with Vulners(KEY) as client:
            out = client.archive.getsploit()
        assert out == b"raw-exploit-db"


class TestArchiveAsync:
    @respx.mock
    async def test_fetch_collection_async(self):
        route = respx.get(f"{BASE}/api/v4/archive/collection").mock(
            return_value=_gzip_json([{"id": "X"}])
        )
        async with AsyncVulners(KEY) as client:
            out = await client.archive.fetch_collection("cve")
        assert out == [{"id": "X"}]
        assert route.calls.last.request.url.params["type"] == "cve"
