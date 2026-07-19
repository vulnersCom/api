"""Lazy NDJSON archive streaming, gzip/zip decode, cap, and stream responses."""

from __future__ import annotations

import gzip
import inspect
import io
import zipfile

import httpx
import orjson
import pytest
import respx

from vulners._client import AsyncVulners, Vulners
from vulners._exceptions import APIResponseValidationError

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com"
COLLECTION = f"{BASE}/api/v4/archive/collection"
LUCENE = f"{BASE}/api/v3/search/lucene/"


def _ndjson(records: list[object]) -> bytes:
    return b"\n".join(orjson.dumps(r) for r in records) + b"\n"


def _gzip_ndjson(records: list[object]) -> httpx.Response:
    return httpx.Response(
        200,
        content=gzip.compress(_ndjson(records)),
        headers={"content-type": "application/x-gzip-compressed"},
    )


def _zip_ndjson(records: list[object]) -> httpx.Response:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("collection.ndjson", _ndjson(records))
    return httpx.Response(
        200, content=buf.getvalue(), headers={"content-type": "application/zip"}
    )


def _plain_ndjson(records: list[object]) -> httpx.Response:
    return httpx.Response(
        200, content=_ndjson(records), headers={"content-type": "application/x-ndjson"}
    )


class TestIterCollectionSync:
    @respx.mock
    def test_gzip_ndjson_records(self):
        records = [{"id": "CVE-1"}, {"id": "CVE-2"}, {"id": "CVE-3"}]
        route = respx.get(COLLECTION).mock(return_value=_gzip_ndjson(records))
        with Vulners(KEY) as client:
            out = list(client.archive.iter_collection("cve"))
        assert out == records
        assert route.calls.last.request.url.params["type"] == "cve"

    @respx.mock
    def test_is_lazy_generator(self):
        route = respx.get(COLLECTION).mock(return_value=_gzip_ndjson([{"id": "A"}, {"id": "B"}]))
        with Vulners(KEY) as client:
            gen = client.archive.iter_collection("cve")
            assert inspect.isgenerator(gen)
            assert route.call_count == 0  # nothing sent until the first item is pulled
            first = next(gen)
            assert first == {"id": "A"}
            assert route.call_count == 1

    @respx.mock
    def test_plain_ndjson_records(self):
        records = [{"id": "X"}, {"id": "Y"}]
        respx.get(COLLECTION).mock(return_value=_plain_ndjson(records))
        with Vulners(KEY) as client:
            assert list(client.archive.iter_collection("cve")) == records

    @respx.mock
    def test_zip_ndjson_records(self):
        records = [{"id": "Z1"}, {"id": "Z2"}]
        respx.get(COLLECTION).mock(return_value=_zip_ndjson(records))
        with Vulners(KEY) as client:
            assert list(client.archive.iter_collection("cve")) == records

    @respx.mock
    def test_ndjson_without_trailing_newline_flushes_last_record(self):
        # No trailing newline: the decoder buffers the last record and emits it
        # from flush() (exercises the sync stream_records flush branch).
        body = b'{"id": "rec-1"}\n{"id": "rec-2"}'
        respx.get(COLLECTION).mock(
            return_value=httpx.Response(
                200, content=body, headers={"content-type": "application/x-ndjson"}
            )
        )
        with Vulners(KEY) as client:
            assert list(client.archive.iter_collection("cve")) == [
                {"id": "rec-1"},
                {"id": "rec-2"},
            ]

    @respx.mock
    def test_max_response_bytes_aborts_decompression_bomb(self):
        # Highly compressible: small on the wire, large once inflated.
        records = [{"id": "CVE-1"}] * 2000
        respx.get(COLLECTION).mock(return_value=_gzip_ndjson(records))
        with Vulners(KEY, max_response_bytes=500) as client:
            with pytest.raises(APIResponseValidationError):
                list(client.archive.iter_collection("cve"))

    @respx.mock
    def test_error_status_raises_before_streaming(self):
        respx.get(COLLECTION).mock(
            return_value=httpx.Response(
                403, content=orjson.dumps({"result": "error", "data": {"error": "no key"}})
            )
        )
        with Vulners(KEY) as client:
            with pytest.raises(Exception) as exc:
                list(client.archive.iter_collection("cve"))
        assert exc.value.__class__.__name__ == "PermissionDeniedError"


class TestIterCollectionAsync:
    @respx.mock
    async def test_gzip_ndjson_records(self):
        records = [{"id": "CVE-1"}, {"id": "CVE-2"}]
        respx.get(COLLECTION).mock(return_value=_gzip_ndjson(records))
        async with AsyncVulners(KEY) as client:
            out = [r async for r in client.archive.aiter_collection("cve")]
        assert out == records

    @respx.mock
    async def test_zip_ndjson_records(self):
        records = [{"id": "Z1"}, {"id": "Z2"}]
        respx.get(COLLECTION).mock(return_value=_zip_ndjson(records))
        async with AsyncVulners(KEY) as client:
            out = [r async for r in client.archive.aiter_collection("cve")]
        assert out == records

    @respx.mock
    async def test_max_response_bytes_aborts(self):
        records = [{"id": "CVE-1"}] * 2000
        respx.get(COLLECTION).mock(return_value=_gzip_ndjson(records))
        async with AsyncVulners(KEY, max_response_bytes=500) as client:
            with pytest.raises(APIResponseValidationError):
                _ = [r async for r in client.archive.aiter_collection("cve")]


class TestStreamRedirect:
    @respx.mock
    def test_follows_302_to_storage_and_strips_key(self):
        records = [{"id": "CVE-1"}]
        gcs = "https://storage.googleapis.com/vulners/cve.ndjson.gz?sig=abc"
        respx.get(COLLECTION).mock(return_value=httpx.Response(302, headers={"location": gcs}))
        gcs_route = respx.get(gcs).mock(return_value=_gzip_ndjson(records))
        with Vulners(KEY) as client:
            out = list(client.archive.iter_collection("cve"))
        assert out == records
        # cross-origin hop drops the credential (transport SSRF/key-strip policy)
        assert "x-api-key" not in gcs_route.calls.last.request.headers


def _search_envelope(*ids: str) -> httpx.Response:
    data = {"search": [{"_source": {"id": i}} for i in ids], "total": len(ids)}
    return httpx.Response(200, content=orjson.dumps({"result": "OK", "data": data}))


class TestWithStreamingResponse:
    @respx.mock
    def test_parse_returns_page(self):
        respx.post(LUCENE).mock(return_value=_search_envelope("CVE-9"))
        with Vulners(KEY) as client:
            with client.search.with_streaming_response.query("ssh") as resp:
                assert resp.status_code == 200
                page = resp.parse()
        assert page.total == 1
        assert page.data[0].id == "CVE-9"

    @respx.mock
    def test_iter_bytes_over_live_body(self):
        body = orjson.dumps({"result": "OK", "data": {"search": [], "total": 0}})
        respx.post(LUCENE).mock(
            return_value=httpx.Response(
                200, content=body, headers={"content-type": "application/json"}
            )
        )
        with Vulners(KEY) as client:
            with client.search.with_streaming_response.query("ssh") as resp:
                collected = b"".join(resp.iter_bytes())
        assert collected == body

    @respx.mock
    async def test_async_parse_returns_page(self):
        respx.post(LUCENE).mock(return_value=_search_envelope("CVE-9"))
        async with AsyncVulners(KEY) as client:
            async with await client.search.with_streaming_response.query("ssh") as resp:
                assert resp.status_code == 200
                page = await resp.parse()
        assert page.data[0].id == "CVE-9"

    @respx.mock
    async def test_async_iter_lines(self):
        body = orjson.dumps({"result": "OK", "data": {"search": [], "total": 0}})
        respx.post(LUCENE).mock(
            return_value=httpx.Response(
                200, content=body, headers={"content-type": "application/json"}
            )
        )
        async with AsyncVulners(KEY) as client:
            async with await client.search.with_streaming_response.query("ssh") as resp:
                lines = [line async for line in resp.iter_lines()]
        assert lines == [body.decode()]
