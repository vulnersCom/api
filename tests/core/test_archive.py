"""Archive resource request-wire, gzip decode and parsing (respx)."""

from __future__ import annotations

import gzip
import io
import zipfile
from datetime import datetime, timezone

import httpx
import orjson
import pytest
import respx

import vulners._transport_client_async as _tca
import vulners._transport_client_sync as _tcs
from vulners._client import AsyncVulners, Vulners
from vulners._exceptions import APIConnectionError

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


# The real archive flow is two legs: GET vulners.com/api/v4/archive/* (the
# billable archive-open) -> 302 to a signed storage.googleapis.com URL -> the
# archive bytes stream from storage. A transient read error on the *storage* leg
# must NOT make the buffered fetch retry by re-issuing the original vulners.com
# request, which would re-run (and re-bill) the archive-open. These tests inject
# exactly that fault through a bring-your-own transport and assert the billable
# leg is hit once, matching the streaming path's pre-first-byte-only retry.
_GCS = "https://storage.googleapis.com/vulners-archive/cve.json.gz?sig=deadbeef"
_ARCHIVE_BODY = gzip.compress(orjson.dumps([{"id": "CVE-1"}]))


class _FaultyBody(httpx.SyncByteStream):
    def __init__(self, head: bytes, exc: BaseException) -> None:
        self._head = head
        self._exc = exc

    def __iter__(self):
        # Emit a partial chunk (storage has already streamed *some* bytes; the
        # vulners.com leg has already billed), then fail mid-download.
        yield self._head
        raise self._exc

    def close(self) -> None:
        pass


class _CleanBody(httpx.SyncByteStream):
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __iter__(self):
        yield self._body

    def close(self) -> None:
        pass


class _AsyncFaultyBody(httpx.AsyncByteStream):
    def __init__(self, head: bytes, exc: BaseException) -> None:
        self._head = head
        self._exc = exc

    async def __aiter__(self):
        yield self._head
        raise self._exc

    async def aclose(self) -> None:
        pass


class _AsyncCleanBody(httpx.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self._body = body

    async def __aiter__(self):
        yield self._body

    async def aclose(self) -> None:
        pass


def _redirect_then_fault_handler(counts: dict[str, int], exc: BaseException, *, is_async: bool):
    """Handler: vulners.com archive -> 302 to storage; storage -> fault then clean.

    The fault fires only on the *first* storage leg. If the buggy retry re-issued
    the whole request, the second storage leg would succeed — so a hit count of 2
    on the vulners.com leg is exactly the double-bill signature, and 1 is the fix.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "vulners.com":
            counts["vulners"] += 1
            return httpx.Response(302, headers={"location": _GCS})
        counts["gcs"] += 1
        headers = {"content-type": "application/x-gzip-compressed"}
        if counts["gcs"] == 1:
            head = _ARCHIVE_BODY[:4]
            stream = _AsyncFaultyBody(head, exc) if is_async else _FaultyBody(head, exc)
            return httpx.Response(200, headers=headers, stream=stream)
        clean = _AsyncCleanBody(_ARCHIVE_BODY) if is_async else _CleanBody(_ARCHIVE_BODY)
        return httpx.Response(200, headers=headers, stream=clean)

    return handler


class TestArchiveFetchNoSilentRebill:
    def test_sync_mid_download_read_error_not_reissued(self):
        counts = {"vulners": 0, "gcs": 0}
        handler = _redirect_then_fault_handler(
            counts, httpx.ReadError("injected mid-download read error"), is_async=False
        )
        byo = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
        with Vulners(KEY, http_client=byo) as client:
            with pytest.raises(APIConnectionError):
                client.archive.fetch_collection("cve")
        # billable archive-open hit exactly once: the mid-download fault was not
        # papered over by silently re-issuing the request (no second 100-cred bill).
        assert counts["vulners"] == 1

    async def test_async_mid_download_read_error_not_reissued(self):
        counts = {"vulners": 0, "gcs": 0}
        handler = _redirect_then_fault_handler(
            counts, httpx.ReadError("injected mid-download read error"), is_async=True
        )
        byo = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)
        async with AsyncVulners(KEY, http_client=byo) as client:
            with pytest.raises(APIConnectionError):
                await client.archive.fetch_collection("cve")
        assert counts["vulners"] == 1

    def test_sync_connect_error_before_dispatch_still_retried(self, monkeypatch):
        # The gate is narrow: a pre-dispatch connection failure (never billed) is
        # still retried on the archive endpoint even though it is idempotent=False.
        monkeypatch.setattr(_tcs, "_retry_timeout", lambda *a, **k: 0.0)
        counts = {"vulners": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            counts["vulners"] += 1
            raise httpx.ConnectError("connection refused")

        byo = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
        with Vulners(KEY, http_client=byo) as client:
            with pytest.raises(APIConnectionError):
                client.archive.fetch_collection("cve")
        # default max_retries=2 -> 1 initial + 2 retries; connect never delivered
        # the request, so re-issuing it cannot double-bill.
        assert counts["vulners"] == 3

    async def test_async_connect_error_before_dispatch_still_retried(self, monkeypatch):
        monkeypatch.setattr(_tca, "_retry_timeout", lambda *a, **k: 0.0)
        counts = {"vulners": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            counts["vulners"] += 1
            raise httpx.ConnectError("connection refused")

        byo = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)
        async with AsyncVulners(KEY, http_client=byo) as client:
            with pytest.raises(APIConnectionError):
                await client.archive.fetch_collection("cve")
        assert counts["vulners"] == 3
