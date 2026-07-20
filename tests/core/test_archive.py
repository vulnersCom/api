"""Archive resource request-wire, gzip decode and parsing (respx)."""

from __future__ import annotations

import gzip
import io
import zipfile
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


def _zip_json(payload: object, name: str = "distributive.json") -> httpx.Response:
    """A single-member zip carrying ``payload`` as JSON — the distributive wire."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, orjson.dumps(payload))
    return httpx.Response(
        200, content=buf.getvalue(), headers={"content-type": "application/zip"}
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
        # Real wire: application/zip whose member is a bare JSON list of _source objects.
        respx.get(f"{BASE}/api/v3/archive/distributive/").mock(
            return_value=_zip_json([{"_source": {"id": "A"}}, {"no_source": 1}])
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
