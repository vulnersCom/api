"""Contract tests for the v4.0 review fixes.

These check the *behaviour* the fixes are about (not just that lines execute):
with_options lifecycle across GC, config validation, search/audit input limits,
the shared-client multi-origin guard, and truncated-archive detection.
"""

from __future__ import annotations

import gc
import gzip

import httpx
import pytest
from pydantic import SecretStr

from vulners import _transport_client_async as tca
from vulners import _transport_client_sync as tcs
from vulners._client import AsyncVulners, Vulners
from vulners._config import ClientConfig
from vulners._exceptions import APIConnectionError, APIResponseValidationError, APIStatusError
from vulners._resources._async.search import exploit_search_query
from vulners._streaming import GzipJsonArrayDecoder

KEY = "SYNTHETIC-TEST-KEY"

_ARCHIVE_CT = {"content-type": "application/x-gzip-compressed"}


def _ok_client() -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": {"search": [], "total": 0}})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _archive_ok(payload: bytes = b'[{"id": 1}]') -> httpx.Response:
    return httpx.Response(200, headers=_ARCHIVE_CT, content=gzip.compress(payload))


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    # Keep retry-path tests instant.
    monkeypatch.setattr(tca, "_retry_timeout", lambda *a, **k: 0.0)
    monkeypatch.setattr(tcs, "_retry_timeout", lambda *a, **k: 0.0)


def _cfg(**kw) -> ClientConfig:
    return ClientConfig(
        api_key=SecretStr("x"), base_url=httpx.URL("https://vulners.com"), user_agent="t", **kw
    )


# -- finding 1: with_options must survive the temporary parent being GC'd --------


def test_with_options_survives_temporary_parent_gc():
    # `Vulners(KEY).with_options(...)` drops the parent immediately; the clone must
    # keep it alive (and its pool open) via _owner instead of closing early — and an
    # explicit close() must actually close the shared pool (via the owner), now.
    client = Vulners(KEY).with_options(timeout=1.0)
    gc.collect()
    assert not client.is_closed
    client.close()
    assert client.is_closed


async def test_async_with_options_survives_temporary_parent_gc():
    client = AsyncVulners(KEY).with_options(timeout=1.0)
    gc.collect()
    assert not client.is_closed
    await client.aclose()
    assert client.is_closed


# -- findings 7 / 16 / 17: config validation -------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"base_url": "http://api.example.com"},  # 7: key over plain HTTP to a public host
        {"base_url": "https://gw.example/prefix/"},  # 16: path prefix silently dropped
        {"base_url": "ftp://example.com"},  # 17: bad scheme
        {"max_retries": -1},  # 17
        {"max_response_bytes": 0},  # 17
    ],
)
def test_config_rejects_bad_values(kwargs):
    with pytest.raises(ValueError):
        Vulners(KEY, **kwargs)


def test_config_allows_http_for_loopback():
    # Local development over http://localhost is allowed (no cleartext key on the wire).
    client = Vulners(KEY, base_url="http://localhost:9200")
    assert client.base_url.scheme == "http"
    client.close()


# -- finding 14: search input validation -----------------------------------------


async def test_search_query_rejects_bad_inputs():
    async with AsyncVulners(KEY, http_client=_ok_client()) as v:
        for bad in ({"query": ""}, {"query": "x", "limit": 0}, {"query": "x", "offset": -1}):
            with pytest.raises(ValueError):
                await v.search.query(**bad)


def test_exploit_search_query_rejects_empty():
    # An empty exploit query must be rejected here — not wrapped into
    # "bulletinFamily:exploit AND ()", which would slip past query()'s check.
    for bad in ("", "   "):
        with pytest.raises(ValueError):
            exploit_search_query(bad)
    assert exploit_search_query("nginx") == "bulletinFamily:exploit AND (nginx)"


async def test_search_exploits_rejects_empty():
    async with AsyncVulners(KEY, http_client=_ok_client()) as v:
        with pytest.raises(ValueError):
            await v.search.exploits("")


# -- finding 15: audit input limits ----------------------------------------------


async def test_audit_rejects_bad_inputs():
    async with AsyncVulners(KEY, http_client=_ok_client()) as v:
        with pytest.raises(ValueError):
            await v.audit.software([])
        with pytest.raises(ValueError):
            await v.audit.linux_audit(os_name="debian", os_version="10", packages=[])
        with pytest.raises(ValueError):
            await v.audit.linux_audit(os_name="debian", os_version="10", packages=["pkg"] * 2501)
        with pytest.raises(ValueError):
            await v.audit.linux_audit(os_name="debian", os_version="10", packages=["ok", "  "])
        with pytest.raises(ValueError):
            await v.audit.cve_batch_audit([])


def test_sync_search_and_audit_validation():
    http = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"result": {}}))
    )
    with Vulners(KEY, http_client=http) as v:
        with pytest.raises(ValueError):
            v.search.query("")
        with pytest.raises(ValueError):
            v.search.query("x", limit=0)
        with pytest.raises(ValueError):
            v.search.query("x", offset=-1)
        with pytest.raises(ValueError):
            v.search.exploits("")  # exercises the sync exploit_search_query guard
        with pytest.raises(ValueError):
            v.audit.software([])
        with pytest.raises(ValueError):
            v.audit.linux_audit(os_name="d", os_version="10", packages=["ok", ""])
        with pytest.raises(ValueError):
            v.audit.linux_audit(os_name="d", os_version="10", packages=["x"] * 2501)


def test_config_extra_validation():
    with pytest.raises(ValueError):
        _cfg(connect_retries=-1)
    with pytest.raises(ValueError):
        _cfg(max_rate_limit_wait=-1.0)
    with pytest.raises(ValueError):  # hostless URL
        ClientConfig(api_key=SecretStr("x"), base_url=httpx.URL("https:///x"), user_agent="t")


def test_config_allows_http_for_private_ip():
    client = Vulners(KEY, base_url="http://10.0.0.1")
    assert client.base_url.host == "10.0.0.1"
    client.close()


# -- finding 6: one shared httpx client, two SDK origins -------------------------


def test_shared_client_multi_origin_keeps_each_key():
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.headers.get("x-api-key")))
        return httpx.Response(200, json={"result": "OK", "data": {}})

    http = httpx.Client(transport=httpx.MockTransport(handler))
    a = Vulners("KEY-A", base_url="https://vulners.com", http_client=http)
    b = Vulners("KEY-B", base_url="https://stage.example", http_client=http)
    a.get("/api/v3/a")
    b.get("/api/v3/b")
    # Each request is same-origin for its own client, so neither key is stripped —
    # the guard compares against the request's own origin, not the first client's.
    assert ("vulners.com", "KEY-A") in seen
    assert ("stage.example", "KEY-B") in seen
    a.close()
    b.close()
    http.close()


# -- finding 11: a truncated gzip archive is detected, not silently accepted ------


def test_gzip_decoder_rejects_truncated_stream():
    full = gzip.compress(b'[\n{"id": 1},\n{"id": 2}\n]')
    truncated = full[:-4]  # drop the CRC/length trailer
    decoder = GzipJsonArrayDecoder()
    with pytest.raises(APIResponseValidationError):
        list(decoder.feed(truncated))
        list(decoder.flush())


def test_gzip_decoder_rejects_trailing_garbage():
    poisoned = gzip.compress(b'[{"id": 1}]') + b"GARBAGE"  # non-NUL tail after a valid member
    decoder = GzipJsonArrayDecoder()
    with pytest.raises(APIResponseValidationError):
        list(decoder.feed(poisoned))


def test_gzip_decoder_tolerates_nul_padding():
    padded = gzip.compress(b'[{"id": 1}]') + b"\x00\x00\x00"
    decoder = GzipJsonArrayDecoder()
    records = list(decoder.feed(padded)) + list(decoder.flush())
    assert records == [{"id": 1}]


# -- finding 9: the stream open phase goes through the retry loop -----------------


def _retry_then_ok(*, exc=None, status=None):
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            if exc is not None:
                raise exc
            return httpx.Response(status, json={"error": "busy"})
        return _archive_ok()

    return handler


_RETRY_CASES = [
    {"exc": httpx.ConnectError("boom")},  # transport error
    {"exc": httpx.ReadTimeout("slow")},  # timeout
    {"status": 503},  # retryable status
]


@pytest.mark.parametrize("kw", _RETRY_CASES)
def test_sync_stream_open_retries(kw):
    http = httpx.Client(transport=httpx.MockTransport(_retry_then_ok(**kw)))
    with Vulners(KEY, http_client=http, max_retries=2) as v:
        assert list(v.archive.iter_collection("cve")) == [{"id": 1}]


@pytest.mark.parametrize("kw", _RETRY_CASES)
async def test_async_stream_open_retries(kw):
    http = httpx.AsyncClient(transport=httpx.MockTransport(_retry_then_ok(**kw)))
    async with AsyncVulners(KEY, http_client=http, max_retries=2) as v:
        assert [r async for r in v.archive.aiter_collection("cve")] == [{"id": 1}]


def test_sync_stream_open_connect_error_exhausts_to_typed_error():
    http = httpx.Client(
        transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x")))
    )
    with Vulners(KEY, http_client=http, max_retries=0) as v:
        with pytest.raises(APIConnectionError):
            list(v.archive.iter_collection("cve"))


async def test_async_stream_open_timeout_exhausts_to_typed_error():
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("x")))
    )
    async with AsyncVulners(KEY, http_client=http, max_retries=0) as v:
        with pytest.raises(APIConnectionError):
            [r async for r in v.archive.aiter_collection("cve")]


def test_sync_stream_open_timeout_exhausts_to_typed_error():
    http = httpx.Client(
        transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("x")))
    )
    with Vulners(KEY, http_client=http, max_retries=0) as v:
        with pytest.raises(APIConnectionError):
            list(v.archive.iter_collection("cve"))


# -- finding 3: streaming error bodies are read with a bounded cap ----------------


def _big_error(request: httpx.Request) -> httpx.Response:
    body = b'{"error":"' + b"x" * (100 * 1024) + b'"}'  # > the 64 KiB error-read cap
    return httpx.Response(500, headers={"content-type": "application/json"}, content=body)


def test_sync_stream_error_body_is_capped():
    http = httpx.Client(transport=httpx.MockTransport(_big_error))
    with Vulners(KEY, http_client=http, max_retries=0) as v:
        with pytest.raises(APIStatusError):
            list(v.archive.iter_collection("cve"))


async def test_async_stream_error_body_is_capped():
    http = httpx.AsyncClient(transport=httpx.MockTransport(_big_error))
    async with AsyncVulners(KEY, http_client=http, max_retries=0) as v:
        with pytest.raises(APIStatusError):
            [r async for r in v.archive.aiter_collection("cve")]


# -- finding 12: download_collection is atomic ------------------------------------


def test_sync_download_collection_atomic(tmp_path):
    dest = tmp_path / "cve.gz"
    dest.write_bytes(b"OLD")
    http = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"NEWDATA"))
    )
    with Vulners(KEY, http_client=http) as v:
        assert v.archive.download_collection("cve", dest) == 7
    assert dest.read_bytes() == b"NEWDATA"
    assert not list(tmp_path.glob(".vulners-dl-*"))  # temp renamed, none left


async def test_async_download_collection_cleanup_on_error(tmp_path):
    dest = tmp_path / "cve.gz"
    dest.write_bytes(b"OLD")
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x")))
    )
    async with AsyncVulners(KEY, http_client=http, max_retries=0) as v:
        with pytest.raises(APIConnectionError):
            await v.archive.download_collection("cve", dest)
    assert dest.read_bytes() == b"OLD"  # original archive untouched
    assert not list(tmp_path.glob(".vulners-dl-*"))  # temp cleaned up


def test_sync_download_collection_cleanup_on_error(tmp_path):
    dest = tmp_path / "cve.gz"
    dest.write_bytes(b"OLD")
    http = httpx.Client(
        transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x")))
    )
    with Vulners(KEY, http_client=http, max_retries=0) as v:
        with pytest.raises(APIConnectionError):
            v.archive.download_collection("cve", dest)
    assert dest.read_bytes() == b"OLD"
    assert not list(tmp_path.glob(".vulners-dl-*"))
