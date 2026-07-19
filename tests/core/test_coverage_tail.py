"""Remaining branch/line coverage for the v4 core.

Targets the last uncovered edges after the resource, unit and I/O suites: the
credential-scrub transport helpers (json/form/query bodies), the ``Vulners`` /
``AsyncVulners`` option-cloning surface, a few streaming-decoder empty-line
branches, the pure archive casters, and a handful of model/exception/resource
branch tails. Synthetic data throughout.
"""

from __future__ import annotations

import gzip
import io
import zipfile
from typing import Annotated

import httpx
import orjson
import pytest
import respx

import vulners._transport as tp
from vulners._client import AsyncVulners, Vulners
from vulners._config import DEFAULT_TIMEOUT
from vulners._exceptions import _extract_message
from vulners._models._base import VulnersModel, construct_type
from vulners._models.bulletin import CveBulletin, construct_bulletin
from vulners._resources._async.archive import _decode_archive as async_decode_archive
from vulners._resources._async.archive import _distributive as async_distributive
from vulners._resources._sync.archive import _decode_archive as sync_decode_archive
from vulners._resources._sync.archive import _distributive as sync_distributive
from vulners._retry import _retry_after_seconds
from vulners._streaming import GzipNdjsonDecoder, PlainNdjsonDecoder, iter_zip_ndjson

KEY = "SYNTHETIC-TEST-KEY"
BASE = "https://vulners.com"
ORIGIN = httpx.URL(BASE)


# ---------------------------------------------------------------------------
# _transport credential-scrub helpers
# ---------------------------------------------------------------------------


class TestTransportHelpers:
    def test_guard_redirect_target_non_ip_returns(self):
        # A normal domain is not an IP literal -> ip_address raises -> guard returns.
        tp._guard_redirect_target(httpx.URL("https://evil.example/x"))  # no raise

    def test_guard_redirect_target_public_ip_allowed(self):
        # A public IP literal parses but is not private/internal -> allowed.
        tp._guard_redirect_target(httpx.URL("https://8.8.8.8/x"))  # no raise

    def test_scrub_removes_query_api_key(self):
        req = httpx.Request("GET", "https://evil.example/x?apiKey=SECRET&q=1")
        tp._scrub_credential(req)
        assert "apiKey" not in req.url.params
        assert req.url.params["q"] == "1"

    def test_scrub_json_body_removes_key(self):
        req = httpx.Request(
            "POST",
            "https://evil.example/x",
            content=orjson.dumps({"apiKey": "SECRET", "q": "keep"}),
            headers={"content-type": "application/json"},
        )
        tp._scrub_credential(req)
        assert orjson.loads(req.read()) == {"q": "keep"}
        assert req.headers["content-length"] == str(len(req._content))

    def test_scrub_json_invalid_body_noop(self):
        req = httpx.Request(
            "POST",
            "https://evil.example/x",
            content=b"<not json>",
            headers={"content-type": "application/json"},
        )
        tp._scrub_credential(req)
        assert req.read() == b"<not json>"

    def test_scrub_json_without_key_noop(self):
        req = httpx.Request(
            "POST",
            "https://evil.example/x",
            content=orjson.dumps({"q": "x"}),
            headers={"content-type": "application/json"},
        )
        tp._scrub_credential(req)
        assert orjson.loads(req.read()) == {"q": "x"}

    def test_scrub_json_non_dict_body_noop(self):
        req = httpx.Request(
            "POST",
            "https://evil.example/x",
            content=orjson.dumps([1, 2]),
            headers={"content-type": "application/json"},
        )
        tp._scrub_credential(req)
        assert orjson.loads(req.read()) == [1, 2]

    def test_scrub_form_urlencoded_removes_key(self):
        req = httpx.Request(
            "POST",
            "https://evil.example/x",
            content=b"apiKey=SECRET&q=keep",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        tp._scrub_credential(req)
        assert req.read() == b"q=keep"

    def test_scrub_form_urlencoded_without_key_noop(self):
        req = httpx.Request(
            "POST",
            "https://evil.example/x",
            content=b"q=keep",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        tp._scrub_credential(req)
        assert req.read() == b"q=keep"

    def test_scrub_other_content_type_noop(self):
        req = httpx.Request(
            "POST",
            "https://evil.example/x",
            content=b"binary",
            headers={"content-type": "application/octet-stream"},
        )
        tp._scrub_credential(req)
        assert req.read() == b"binary"

    def test_scrub_json_body_when_bytestream_unavailable(self, monkeypatch):
        # Defensive path: if the httpx internal moved, the header/query strip still
        # happens and the body scrub becomes a stream no-op (not an error).
        monkeypatch.setattr(tp, "_HttpxByteStream", None)
        req = httpx.Request(
            "POST",
            "https://evil.example/x",
            content=orjson.dumps({"apiKey": "SECRET", "q": "keep"}),
            headers={"content-type": "application/json"},
        )
        tp._scrub_credential(req)
        assert orjson.loads(req._content) == {"q": "keep"}


class TestAsyncTransportScrub:
    async def test_cross_origin_scrubs_json_body(self):
        records: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            request.read()
            records.append(request)
            return httpx.Response(200, content=orjson.dumps({"result": "OK"}))

        transport = tp.AsyncVulnersTransport(httpx.MockTransport(handler), origin=ORIGIN)
        req = httpx.Request(
            "POST",
            "https://evil.example/x",
            content=orjson.dumps({"apiKey": "SECRET", "q": "1"}),
            headers={"X-Api-Key": "SECRET", "content-type": "application/json"},
        )
        await transport.handle_async_request(req)
        assert orjson.loads(records[0].content) == {"q": "1"}
        assert "x-api-key" not in records[0].headers


# ---------------------------------------------------------------------------
# _client option cloning and properties
# ---------------------------------------------------------------------------


class TestClientOptions:
    def test_sync_base_url_and_with_options(self):
        client = Vulners(KEY)
        try:
            assert str(client.base_url).startswith(BASE)
            clone = client.with_options(timeout=5.0, max_response_bytes=1000)
            assert clone.config.timeout == httpx.Timeout(5.0)
            assert clone.config.max_response_bytes == 1000
            # timeout=None means "no timeout"
            clone2 = client.with_options(timeout=None)
            assert clone2.config.timeout == httpx.Timeout(None)
            # a Timeout instance is passed through
            t = httpx.Timeout(9.0)
            assert client.with_options(timeout=t).config.timeout == t
            # omitting timeout keeps the default
            assert client.with_options(max_retries=1).config.timeout == DEFAULT_TIMEOUT
        finally:
            client.close()

    async def test_async_config_base_url_and_with_options(self):
        client = AsyncVulners(KEY)
        try:
            assert client.config.max_retries >= 0
            assert str(client.base_url).startswith(BASE)
            clone = client.with_options(timeout=5.0, max_retries=4, max_response_bytes=2000)
            assert clone.config.timeout == httpx.Timeout(5.0)
            assert clone.config.max_retries == 4
            assert clone.config.max_response_bytes == 2000
            assert clone._api._client is client._api._client  # shared pool
            # omit max_retries/max_response_bytes -> those overrides are skipped
            clone2 = client.with_options(timeout=1.0)
            assert clone2.config.max_retries == client.config.max_retries
        finally:
            await client.aclose()


# ---------------------------------------------------------------------------
# _streaming empty-line branches
# ---------------------------------------------------------------------------


class TestStreamingEmptyLines:
    def test_plain_flush_blank_final_line(self):
        d = PlainNdjsonDecoder()
        list(d.feed(b'{"a":1}\n'))
        list(d.feed(b"   "))  # whitespace-only tail, no newline -> flush parses to blank
        assert list(d.flush()) == []

    def test_gzip_blank_line_and_large_tail(self):
        # Blank line inside the stream (_EMPTY skipped) + a payload big enough that
        # a single feed leaves an unconsumed_tail under the cap loop.
        raw = b'{"a":1}\n\n' + (b'{"x":1}\n' * 40000)
        d = GzipNdjsonDecoder(cap=100_000_000)
        out = list(d.feed(gzip.compress(raw)))
        out += list(d.flush())
        assert out[0] == {"a": 1}
        assert len(out) == 40001

    def test_gzip_flush_trailing_partial_line(self):
        d = GzipNdjsonDecoder()
        out = list(d.feed(gzip.compress(b'{"a":1}\n{"b":2}')))  # no trailing newline
        out += list(d.flush())
        assert out == [{"a": 1}, {"b": 2}]

    def test_gzip_flush_blank_trailing_partial_line(self):
        # A whitespace-only final line with no newline: flush parses it to blank -> skipped.
        d = GzipNdjsonDecoder()
        out = list(d.feed(gzip.compress(b'{"a":1}\n  ')))
        out += list(d.flush())
        assert out == [{"a": 1}]

    def test_zip_skips_blank_lines(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            # blank line mid-stream, plus a whitespace-only final line (no newline)
            # so the flush path also parses a blank line and skips it.
            z.writestr("c.ndjson", b'{"a":1}\n\n{"b":2}\n  ')
        assert list(iter_zip_ndjson(buf.getvalue())) == [{"a": 1}, {"b": 2}]


# ---------------------------------------------------------------------------
# archive pure casters (defensive non-bytes / non-list branches)
# ---------------------------------------------------------------------------


class TestArchiveCasters:
    @pytest.mark.parametrize("decode", [async_decode_archive, sync_decode_archive])
    def test_decode_archive_passes_non_bytes_through(self, decode):
        assert decode({"already": "parsed"}) == {"already": "parsed"}

    @pytest.mark.parametrize("decode", [async_decode_archive, sync_decode_archive])
    def test_decode_archive_non_json_bytes(self, decode):
        assert decode(b"not-json") == b"not-json"

    @pytest.mark.parametrize("dist", [async_distributive, sync_distributive])
    def test_distributive_non_list(self, dist):
        assert dist({"not": "a list"}) == []


# ---------------------------------------------------------------------------
# model + exception branch tails
# ---------------------------------------------------------------------------


class _M(VulnersModel):
    x: int | None = None


class TestModelExceptionTails:
    def test_construct_type_strips_bare_annotated(self):
        out = construct_type({"x": 1}, Annotated[_M, "meta"])
        assert isinstance(out, _M)
        assert out.x == 1

    def test_strict_bulletin_from_model_instance(self):
        # Passing an already-built model to the strict adapter drives the callable
        # discriminator over a non-Mapping value (the _family_tag getattr branch).
        instance = construct_bulletin({"bulletinFamily": "NVD", "id": "CVE-1"})
        assert isinstance(instance, CveBulletin)
        validated = construct_bulletin(instance, strict=True)
        assert isinstance(validated, CveBulletin)

    def test_extract_message_dict_without_error_or_items(self):
        assert _extract_message({"nope": 1}) == (None, None)

    def test_retry_after_seconds_empty_headers(self):
        assert _retry_after_seconds(httpx.Headers({})) is None


# ---------------------------------------------------------------------------
# resource optional-branch tails (both clients)
# ---------------------------------------------------------------------------


def _v3(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": "OK", "data": payload}))


class TestResourceOptionalTails:
    @respx.mock
    async def test_async_win_audit_without_platform(self):
        route = respx.post(f"{BASE}/api/v3/audit/winaudit/").mock(return_value=_v3({}))
        async with AsyncVulners(KEY) as client:
            await client.audit.win_audit(
                os="Windows 10", os_version="10.0.19045", kb_list=["KB1"], software=[]
            )
        assert "platform" not in orjson.loads(route.calls.last.request.content)

    @respx.mock
    async def test_async_subscriptions_edit_without_active(self):
        route = respx.post(f"{BASE}/api/v3/subscriptions/editEmailSubscription/").mock(
            return_value=_v3({})
        )
        async with AsyncVulners(KEY) as client:
            await client.subscriptions.edit("s1", format="json")
        assert "active" not in orjson.loads(route.calls.last.request.content)

    @respx.mock
    def test_sync_subscriptions_edit_without_active(self):
        route = respx.post(f"{BASE}/api/v3/subscriptions/editEmailSubscription/").mock(
            return_value=_v3({})
        )
        with Vulners(KEY) as client:
            client.subscriptions.edit("s1", format="json", crontab="* * * * *")
        assert "active" not in orjson.loads(route.calls.last.request.content)

    @respx.mock
    def test_sync_get_bulletin_with_fields(self):
        respx.post(f"{BASE}/api/v3/search/id/").mock(
            return_value=_v3({"documents": {"A": {"id": "A"}}})
        )
        with Vulners(KEY) as client:
            b = client.search.get_bulletin("A", fields=["id"])
        assert b is not None and b.id == "A"
