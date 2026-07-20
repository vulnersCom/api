"""I/O-path coverage for the sync and async request loops in ``_base_client``.

Covers the capped streaming read, the async reactive-retry loop (mirroring the
sync one in ``test_retry.py``), the low-level HTTP verb helpers, the client
context managers, the zip/error branches of ``stream_records``, and the
streaming-response error paths. respx intercepts the wire; backoff sleeps are
collapsed to zero so retries do not actually wait.
"""

from __future__ import annotations

import gzip
import io
import zipfile

import httpx
import orjson
import pytest
import respx

import vulners._base_client as bc
import vulners._transport_client_async as _tca
import vulners._transport_client_sync as _tcs
from vulners._client import AsyncVulners, Vulners
from vulners._config import resolve_config
from vulners._exceptions import (
    APIConnectionError,
    APIResponseValidationError,
    APIStatusError,
    APITimeoutError,
    InternalServerError,
)
from vulners._transport_client_async import AsyncAPIClient
from vulners._transport_client_sync import SyncAPIClient

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com"
COLLECTION = f"{BASE}/api/v4/archive/collection"
LUCENE = f"{BASE}/api/v3/search/lucene/"


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch):
    # _retry_timeout now lives in the split transport-client modules.
    monkeypatch.setattr(_tcs, "_retry_timeout", lambda *a, **k: 0.0)
    monkeypatch.setattr(_tca, "_retry_timeout", lambda *a, **k: 0.0)


def _gzip(payload: object) -> httpx.Response:
    return httpx.Response(
        200,
        content=gzip.compress(orjson.dumps(payload)),
        headers={"content-type": "application/x-gzip-compressed"},
    )


def _json_array(records: list[object]) -> bytes:
    return b"[\n" + b",\n".join(orjson.dumps(r) for r in records) + b"\n]"


def _zip_array(records: list[object]) -> httpx.Response:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("cve.json", _json_array(records))
    return httpx.Response(
        200, content=buf.getvalue(), headers={"content-type": "application/x-zip-compressed"}
    )


# ---------------------------------------------------------------------------
# Capped streaming read (_send with max_response_bytes)
# ---------------------------------------------------------------------------


class TestCappedSend:
    @respx.mock
    def test_sync_capped_fetch_ok(self):
        respx.get(COLLECTION).mock(return_value=_gzip([{"id": "CVE-1"}]))
        with Vulners(KEY, max_response_bytes=10_000_000) as client:
            assert client.archive.fetch_collection("cve") == [{"id": "CVE-1"}]

    @respx.mock
    async def test_async_capped_fetch_ok(self):
        respx.get(COLLECTION).mock(return_value=_gzip([{"id": "CVE-2"}]))
        async with AsyncVulners(KEY, max_response_bytes=10_000_000) as client:
            assert await client.archive.fetch_collection("cve") == [{"id": "CVE-2"}]

    @respx.mock
    def test_sync_capped_declared_length_rejected(self):
        respx.get(COLLECTION).mock(
            return_value=httpx.Response(
                200, content=b"x" * 2000, headers={"content-type": "application/octet-stream"}
            )
        )
        with Vulners(KEY, max_response_bytes=100) as client:
            with pytest.raises(APIResponseValidationError):
                client.archive.fetch_collection("cve")

    @respx.mock
    async def test_async_capped_declared_length_rejected(self):
        respx.get(COLLECTION).mock(
            return_value=httpx.Response(
                200, content=b"x" * 2000, headers={"content-type": "application/octet-stream"}
            )
        )
        async with AsyncVulners(KEY, max_response_bytes=100) as client:
            with pytest.raises(APIResponseValidationError):
                await client.archive.fetch_collection("cve")


# ---------------------------------------------------------------------------
# Async reactive-retry loop
# ---------------------------------------------------------------------------


def _ok() -> httpx.Response:
    return httpx.Response(
        200, content=orjson.dumps({"result": "OK", "data": {"search": [], "total": 0}})
    )


class TestAsyncRetry:
    @respx.mock
    async def test_502_then_success(self):
        route = respx.post(LUCENE).mock(side_effect=[httpx.Response(502, text="bad"), _ok()])
        async with AsyncVulners(KEY) as client:
            page = await client.search.query("ssh")
        assert route.call_count == 2
        assert page.total == 0

    @respx.mock
    async def test_exhausts_retries_then_raises(self):
        route = respx.post(LUCENE).mock(return_value=httpx.Response(500, text="boom"))
        async with AsyncVulners(KEY) as client:
            with pytest.raises(InternalServerError):
                await client.search.query("ssh")
        assert route.call_count == 3  # 1 + 2 retries

    @respx.mock
    async def test_read_timeout_retried_on_idempotent(self):
        route = respx.post(LUCENE).mock(side_effect=httpx.ReadTimeout("timed out"))
        async with AsyncVulners(KEY) as client:
            with pytest.raises(APITimeoutError):
                await client.search.query("ssh")
        assert route.call_count == 3

    @respx.mock
    async def test_connect_error_retried_on_non_idempotent(self):
        url = f"{BASE}/api/v3/non-idempotent/"
        route = respx.post(url).mock(side_effect=httpx.ConnectError("refused"))
        spec = bc.RequestSpec("POST", "/api/v3/non-idempotent/", body_mode="json")
        async with AsyncVulners(KEY) as client:
            with pytest.raises(APIConnectionError):
                await client._api.request(spec, body={})
        assert route.call_count == 3

    @respx.mock
    async def test_read_timeout_not_retried_on_non_idempotent(self):
        url = f"{BASE}/api/v3/non-idempotent/"
        route = respx.post(url).mock(side_effect=httpx.ReadTimeout("t"))
        spec = bc.RequestSpec("POST", "/api/v3/non-idempotent/", body_mode="json")
        async with AsyncVulners(KEY) as client:
            with pytest.raises(APITimeoutError):
                await client._api.request(spec, body={})
        assert route.call_count == 1


# ---------------------------------------------------------------------------
# Low-level HTTP verb helpers + request_with_response
# ---------------------------------------------------------------------------


class TestVerbHelpers:
    @respx.mock
    def test_sync_verbs(self):
        respx.get(f"{BASE}/api/g").mock(return_value=httpx.Response(200, json={"g": 1}))
        respx.post(f"{BASE}/api/p").mock(return_value=httpx.Response(200, json={"p": 1}))
        respx.put(f"{BASE}/api/u").mock(return_value=httpx.Response(200, json={"u": 1}))
        respx.delete(f"{BASE}/api/d").mock(return_value=httpx.Response(200, json={"d": 1}))
        client = SyncAPIClient(resolve_config(api_key=KEY))
        try:
            assert client.get("/api/g") == {"g": 1}
            assert client.post("/api/p", body={"a": 1}) == {"p": 1}
            assert client.put("/api/u", body={"a": 1}) == {"u": 1}
            assert client.delete("/api/d") == {"d": 1}
        finally:
            client.close()

    @respx.mock
    async def test_async_verbs(self):
        respx.get(f"{BASE}/api/g").mock(return_value=httpx.Response(200, json={"g": 1}))
        respx.post(f"{BASE}/api/p").mock(return_value=httpx.Response(200, json={"p": 1}))
        respx.put(f"{BASE}/api/u").mock(return_value=httpx.Response(200, json={"u": 1}))
        respx.delete(f"{BASE}/api/d").mock(return_value=httpx.Response(200, json={"d": 1}))
        client = AsyncAPIClient(resolve_config(api_key=KEY))
        try:
            assert await client.get("/api/g") == {"g": 1}
            assert await client.post("/api/p", body={"a": 1}) == {"p": 1}
            assert await client.put("/api/u", body={"a": 1}) == {"u": 1}
            assert await client.delete("/api/d") == {"d": 1}
        finally:
            await client.aclose()

    @respx.mock
    def test_sync_request_with_response(self):
        respx.post(LUCENE).mock(
            return_value=httpx.Response(
                200, content=orjson.dumps({"result": "OK", "data": {"ok": 1}})
            )
        )
        client = SyncAPIClient(resolve_config(api_key=KEY))
        try:
            resp = client.request_with_response(
                bc.RequestSpec(
                    "POST", "/api/v3/search/lucene/", body_mode="json", unwrap=("data",)
                ),
                body={"query": "x"},
            )
            assert resp.status_code == 200
            assert resp.parse() == {"ok": 1}
        finally:
            client.close()

    @respx.mock
    async def test_async_request_with_response(self):
        respx.post(LUCENE).mock(
            return_value=httpx.Response(
                200, content=orjson.dumps({"result": "OK", "data": {"ok": 2}})
            )
        )
        client = AsyncAPIClient(resolve_config(api_key=KEY))
        try:
            resp = await client.request_with_response(
                bc.RequestSpec(
                    "POST", "/api/v3/search/lucene/", body_mode="json", unwrap=("data",)
                ),
                body={"query": "x"},
            )
            assert resp.parse() == {"ok": 2}
        finally:
            await client.aclose()


# ---------------------------------------------------------------------------
# Client context managers (the low-level API clients)
# ---------------------------------------------------------------------------


class TestLenientResponseDecode:
    @respx.mock
    def test_sync_body_with_bigint_and_infinity(self):
        # orjson rejects Infinity literals and >64-bit ints (both occur in real
        # CVE data); the decode pipeline falls back to the stdlib parser.
        import json

        body = json.dumps({"result": "OK", "data": {"big": 2**80, "inf": float("inf")}})
        respx.get(f"{BASE}/api/edge").mock(
            return_value=httpx.Response(
                200, content=body.encode(), headers={"content-type": "application/json"}
            )
        )
        with Vulners(KEY) as client:
            out = client.get("/api/edge")
        assert out["data"]["big"] == 2**80
        assert out["data"]["inf"] == float("inf")

    @respx.mock
    async def test_async_body_with_bigint_and_infinity(self):
        import json

        body = json.dumps({"result": "OK", "data": {"big": 2**80, "inf": float("inf")}})
        respx.get(f"{BASE}/api/edge").mock(
            return_value=httpx.Response(
                200, content=body.encode(), headers={"content-type": "application/json"}
            )
        )
        async with AsyncVulners(KEY) as client:
            out = await client.get("/api/edge")
        assert out["data"]["big"] == 2**80
        assert out["data"]["inf"] == float("inf")


class TestClientContextManagers:
    def test_sync_context_manager(self):
        with SyncAPIClient(resolve_config(api_key=KEY)) as client:
            assert client.is_closed is False
        assert client.is_closed is True

    async def test_async_context_manager(self):
        async with AsyncAPIClient(resolve_config(api_key=KEY)) as client:
            assert client.is_closed is False
        assert client.is_closed is True


# ---------------------------------------------------------------------------
# stream_records: zip-with-cap and error branches (async side)
# ---------------------------------------------------------------------------


class TestStreamRecordsBranches:
    @respx.mock
    def test_sync_zip_with_cap(self):
        respx.get(COLLECTION).mock(return_value=_zip_array([{"id": "Z1"}, {"id": "Z2"}]))
        with Vulners(KEY, max_response_bytes=10_000_000) as client:
            assert list(client.archive.iter_collection("cve")) == [{"id": "Z1"}, {"id": "Z2"}]

    @respx.mock
    def test_sync_cap_aborts_zip(self):
        # Sync mirror of test_async_cap_aborts_zip: an over-limit zip collection
        # aborts the sync stream end-to-end.
        respx.get(COLLECTION).mock(return_value=_zip_array([{"id": "X"}] * 500))
        with Vulners(KEY, max_response_bytes=50) as client:
            with pytest.raises(APIResponseValidationError):
                list(client.archive.iter_collection("cve"))

    @respx.mock
    async def test_async_zip_with_cap(self):
        respx.get(COLLECTION).mock(return_value=_zip_array([{"id": "Z1"}]))
        async with AsyncVulners(KEY, max_response_bytes=10_000_000) as client:
            out = [r async for r in client.archive.aiter_collection("cve")]
        assert out == [{"id": "Z1"}]

    @respx.mock
    async def test_async_plain_json_array(self):
        # An uncompressed JSON array (application/json) streams and flushes via the
        # non-zip (plain) decoder path.
        body = b'[\n{"id": "A"},\n{"id": "B"}\n]'
        respx.get(COLLECTION).mock(
            return_value=httpx.Response(
                200, content=body, headers={"content-type": "application/json"}
            )
        )
        async with AsyncVulners(KEY) as client:
            out = [r async for r in client.archive.aiter_collection("cve")]
        assert out == [{"id": "A"}, {"id": "B"}]

    @respx.mock
    async def test_async_error_status_raises(self):
        respx.get(COLLECTION).mock(
            return_value=httpx.Response(
                403, content=orjson.dumps({"result": "error", "data": {"error": "no key"}})
            )
        )
        async with AsyncVulners(KEY) as client:
            with pytest.raises(APIStatusError):
                _ = [r async for r in client.archive.aiter_collection("cve")]

    @respx.mock
    async def test_async_cap_aborts_zip(self):
        respx.get(COLLECTION).mock(return_value=_zip_array([{"id": "X"}] * 500))
        async with AsyncVulners(KEY, max_response_bytes=50) as client:
            with pytest.raises(APIResponseValidationError):
                _ = [r async for r in client.archive.aiter_collection("cve")]


# ---------------------------------------------------------------------------
# Streaming-response error paths (with_streaming_response on a 4xx/5xx)
# ---------------------------------------------------------------------------


class TestStreamContextExitWithoutEnter:
    """Robustness: __exit__/__aexit__ before a successful __enter__ (no response)."""

    def test_sync(self):
        client = SyncAPIClient(resolve_config(api_key=KEY))
        try:
            ctx = client.stream_response(bc.RequestSpec("GET", "/x", body_mode="query"))
            ctx.__exit__(None, None, None)  # _response is None -> no-op
        finally:
            client.close()

    async def test_async(self):
        client = AsyncAPIClient(resolve_config(api_key=KEY))
        try:
            ctx = client.stream_response(bc.RequestSpec("GET", "/x", body_mode="query"))
            await ctx.__aexit__(None, None, None)  # _response is None -> no-op
        finally:
            await client.aclose()


class TestStreamingResponseErrors:
    @respx.mock
    def test_sync_stream_response_error(self):
        respx.post(LUCENE).mock(
            return_value=httpx.Response(500, content=orjson.dumps({"error": "boom"}))
        )
        with Vulners(KEY) as client:
            with pytest.raises(APIStatusError):
                with client.search.with_streaming_response.query("ssh"):
                    pass

    @respx.mock
    async def test_async_stream_response_error(self):
        respx.post(LUCENE).mock(
            return_value=httpx.Response(500, content=orjson.dumps({"error": "boom"}))
        )
        async with AsyncVulners(KEY) as client:
            with pytest.raises(APIStatusError):
                async with await client.search.with_streaming_response.query("ssh"):
                    pass
