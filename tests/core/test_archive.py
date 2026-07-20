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


class TestDownloadCollection:
    """download_collection streams the still-compressed archive to disk."""

    @respx.mock
    def test_sync_writes_raw_bytes(self, tmp_path):
        raw = gzip.compress(orjson.dumps([{"id": "CVE-1"}] * 50))
        route = respx.get(f"{BASE}/api/v4/archive/collection").mock(
            return_value=httpx.Response(
                200, content=raw, headers={"content-type": "application/x-gzip-compressed"}
            )
        )
        dest = tmp_path / "cve.json.gz"
        with Vulners(KEY) as client:
            written = client.archive.download_collection("cve", dest)
        assert written == len(raw)
        assert dest.read_bytes() == raw  # byte-for-byte, still compressed
        assert route.calls.last.request.url.params["type"] == "cve"

    @respx.mock
    def test_sync_update_from_uses_update_endpoint(self, tmp_path):
        raw = gzip.compress(orjson.dumps([]))
        route = respx.get(f"{BASE}/api/v4/archive/collection-update").mock(
            return_value=httpx.Response(
                200, content=raw, headers={"content-type": "application/x-gzip-compressed"}
            )
        )
        after = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        with Vulners(KEY) as client:
            written = client.archive.download_collection(
                "cve", tmp_path / "update.gz", update_from=after
            )
        assert written == len(raw)
        params = route.calls.last.request.url.params
        assert params["type"] == "cve"
        assert params["after"] == after.isoformat()

    @respx.mock
    async def test_async_writes_raw_bytes(self, tmp_path):
        raw = gzip.compress(orjson.dumps([{"id": "CVE-9"}]))
        respx.get(f"{BASE}/api/v4/archive/collection").mock(
            return_value=httpx.Response(
                200, content=raw, headers={"content-type": "application/x-gzip-compressed"}
            )
        )
        dest = tmp_path / "cve.json.gz"
        async with AsyncVulners(KEY) as client:
            written = await client.archive.download_collection("cve", dest)
        assert written == len(raw)
        assert dest.read_bytes() == raw

    @respx.mock
    async def test_async_update_from_uses_update_endpoint(self, tmp_path):
        raw = gzip.compress(orjson.dumps([]))
        route = respx.get(f"{BASE}/api/v4/archive/collection-update").mock(
            return_value=httpx.Response(
                200, content=raw, headers={"content-type": "application/x-gzip-compressed"}
            )
        )
        after = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        async with AsyncVulners(KEY) as client:
            await client.archive.download_collection(
                "cve", tmp_path / "update.gz", update_from=after
            )
        assert route.calls.last.request.url.params["after"] == after.isoformat()


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


class TestArchiveFamilyAndState:
    @respx.mock
    def test_collection_state_unwraps_result(self):
        route = respx.get(f"{BASE}/api/v4/archive/collection-state").mock(
            return_value=httpx.Response(
                200, content=orjson.dumps({"result": {"cursor": "2026-01-01T00:00:00Z"}})
            )
        )
        with Vulners(KEY) as client:
            out = client.archive.collection_state("cve")
        assert out == {"cursor": "2026-01-01T00:00:00Z"}
        assert route.calls.last.request.url.params["type"] == "cve"

    @respx.mock
    def test_family_gzip_parse_and_name_param(self):
        route = respx.get(f"{BASE}/api/v4/archive/family").mock(
            return_value=_gzip_json([{"id": "EDB-1"}])
        )
        with Vulners(KEY) as client:
            out = client.archive.family("exploit")
        assert out == [{"id": "EDB-1"}]
        assert route.calls.last.request.url.params["name"] == "exploit"

    @respx.mock
    def test_family_update_sends_after(self):
        route = respx.get(f"{BASE}/api/v4/archive/family-update").mock(
            return_value=_gzip_json([])
        )
        after = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        with Vulners(KEY) as client:
            client.archive.family_update("exploit", after)
        params = route.calls.last.request.url.params
        assert params["name"] == "exploit"
        assert params["after"] == after.isoformat()

    @respx.mock
    def test_family_state_unwraps_result(self):
        route = respx.get(f"{BASE}/api/v4/archive/family-state").mock(
            return_value=httpx.Response(200, content=orjson.dumps({"result": {"total_docs": 7}}))
        )
        with Vulners(KEY) as client:
            assert client.archive.family_state("exploit") == {"total_docs": 7}
        assert route.calls.last.request.url.params["name"] == "exploit"
