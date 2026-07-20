"""Direct unit tests for the v4 core's sans-IO helpers and small modules.

These target the pure/branchy code that the higher-level respx tests reach only
incidentally: request building, response decoding, error normalization, retry
math, model construction, pagination containers, the token buckets, sentinels,
the config resolver, the logger's redaction filter, and the response wrappers.
Synthetic data throughout (fake keys/ids); only response shapes are realistic.
"""

from __future__ import annotations

import gzip
import io
import logging
import zipfile
from typing import Annotated, Any

import httpx
import orjson
import pytest
from pydantic import Field, SecretStr

from vulners._base_client import BaseClient, RequestSpec, _clean_params
from vulners._config import (
    ARCHIVE_TIMEOUT,
    DEFAULT_TIMEOUT,
    resolve_config,
)
from vulners._exceptions import (
    APIConnectionError,
    APIResponseValidationError,
    APIStatusError,
    BadRequestError,
    ConflictError,
    ErrorInfo,
    InternalServerError,
    RateLimitError,
    VulnersError,
    _extract_error,
    _extract_message,
    _has_error_markers,
    _make_error,
    _parse_retry_after,
    _status_class,
)
from vulners._logging import _SecretRedactingFilter, install_key_redaction, logger
from vulners._models._base import (
    Discriminator,
    VulnersModel,
    construct_type,
    register_discriminator,
)
from vulners._pagination import (
    AsyncSearchPage,
    SearchPage,
)
from vulners._ratelimit import RateLimitBucket
from vulners._ratelimit_async import AsyncRateLimitBucket
from vulners._response import APIResponse, AsyncStreamedAPIResponse, StreamedAPIResponse
from vulners._retry import (
    _header_override,
    _retry_after_seconds,
    _retry_timeout,
    _should_retry,
)
from vulners._streaming import (
    GzipJsonArrayDecoder,
    PlainJsonArrayDecoder,
    is_zip_media,
    iter_zip_json_array,
    make_array_decoder,
)
from vulners._types import NotGiven, Omit, not_given, omit

KEY = "SYNTHETIC-TEST-KEY"


def _client() -> BaseClient:
    return BaseClient(resolve_config(api_key=KEY, version="test"))


# ---------------------------------------------------------------------------
# _base_client sans-IO helpers
# ---------------------------------------------------------------------------


class TestRequestSpecAndParams:
    def test_repr(self):
        assert repr(RequestSpec("POST", "/x")) == "RequestSpec(POST /x)"

    def test_clean_params_drops_none_notgiven_omit(self):
        out = _clean_params({"a": 1, "b": None, "c": not_given, "d": omit, "e": "x"})
        assert out == {"a": 1, "e": "x"}


class TestResolveTimeout:
    def test_not_given_uses_profile(self):
        c = _client()
        spec = RequestSpec("GET", "/x", timeout_profile="archive")
        assert c._resolve_timeout(spec, not_given) == ARCHIVE_TIMEOUT
        assert c._resolve_timeout(RequestSpec("GET", "/x"), not_given) == DEFAULT_TIMEOUT

    def test_none_means_no_timeout(self):
        c = _client()
        resolved = c._resolve_timeout(RequestSpec("GET", "/x"), None)
        assert resolved == httpx.Timeout(None)

    def test_float_and_timeout_instances(self):
        c = _client()
        assert c._resolve_timeout(RequestSpec("GET", "/x"), 5.0) == httpx.Timeout(5.0)
        t = httpx.Timeout(3.0)
        assert c._resolve_timeout(RequestSpec("GET", "/x"), t) is t


class TestBuildRequest:
    def test_header_override_and_omit(self):
        c = _client()
        spec = RequestSpec("GET", "/x")
        req = c._build_request(spec, headers={"X-Extra": "1", "Accept": omit})
        assert req.headers["x-extra"] == "1"
        assert "accept" not in req.headers  # omit dropped the default Accept

    def test_text_body_mode(self):
        c = _client()
        spec = RequestSpec("POST", "/x", body_mode="text")
        req = c._build_request(spec, body="hello")
        assert req.read() == b"hello"
        assert req.headers["content-type"].startswith("text/plain")

    def test_text_body_mode_bytes(self):
        c = _client()
        spec = RequestSpec("POST", "/x", body_mode="text")
        req = c._build_request(spec, body=b"\x00\x01")
        assert req.read() == b"\x00\x01"

    def test_query_body_mode_merges_into_url(self):
        c = _client()
        spec = RequestSpec("GET", "/x", body_mode="query")
        req = c._build_request(spec, body={"a": "1"}, params={"b": "2"})
        assert req.url.params["a"] == "1"
        assert req.url.params["b"] == "2"

    def test_encode_json_fallback_for_big_int(self):
        # orjson rejects ints beyond 64-bit range; the json fallback handles them.
        out = BaseClient._encode_json({"n": 2**70})
        assert orjson.loads(out) == {"n": 2**70}


class TestProcessResponse:
    def _resp(self, status=200, ct="application/json", content=b"") -> httpx.Response:
        return httpx.Response(status, headers={"content-type": ct}, content=content)

    def test_json_unwrap(self):
        c = _client()
        spec = RequestSpec("POST", "/x", unwrap=("data",))
        out = c._process_response(
            spec, self._resp(content=b'{"data":{"x":1}}'), b'{"data":{"x":1}}'
        )
        assert out == {"x": 1}

    def test_unwrap_break_on_missing_key(self):
        c = _client()
        spec = RequestSpec("POST", "/x", unwrap=("data", "missing"))
        body = b'{"data":{"x":1}}'
        assert c._process_response(spec, self._resp(content=body), body) == {"x": 1}

    def test_empty_json_body_is_none(self):
        c = _client()
        spec = RequestSpec("GET", "/x")
        assert c._process_response(spec, self._resp(content=b""), b"") is None

    def test_json_400_unparseable_raises_status_error(self):
        c = _client()
        spec = RequestSpec("GET", "/x")
        r = self._resp(status=400, content=b"<not json>")
        with pytest.raises(APIStatusError):
            c._process_response(spec, r, b"<not json>")

    def test_json_200_unparseable_raises_validation(self):
        c = _client()
        spec = RequestSpec("GET", "/x")
        with pytest.raises(APIResponseValidationError):
            c._process_response(spec, self._resp(content=b"<not json>"), b"<not json>")

    def test_json_error_envelope_in_200(self):
        c = _client()
        spec = RequestSpec("GET", "/x")
        body = orjson.dumps({"result": "error", "data": {"error": "bad", "errorCode": 104}})
        with pytest.raises(BadRequestError):
            c._process_response(spec, self._resp(content=body), body)

    def test_non_json_400_raises(self):
        c = _client()
        spec = RequestSpec("GET", "/x")
        r = self._resp(status=403, ct="text/html", content=b"Just a moment")
        with pytest.raises(APIStatusError):
            c._process_response(spec, r, b"Just a moment")

    def test_json_mode_non_json_2xx_empty_is_none(self):
        c = _client()
        spec = RequestSpec("GET", "/x")
        r = self._resp(ct="text/plain", content=b"")
        assert c._process_response(spec, r, b"") is None

    def test_json_mode_non_json_2xx_valid_json_bytes(self):
        c = _client()
        spec = RequestSpec("GET", "/x", unwrap=("data",))
        r = self._resp(ct="text/plain", content=b'{"data":42}')
        assert c._process_response(spec, r, b'{"data":42}') == 42

    def test_json_mode_non_json_2xx_invalid_raises(self):
        c = _client()
        spec = RequestSpec("GET", "/x")
        r = self._resp(ct="text/plain", content=b"nope")
        with pytest.raises(APIResponseValidationError):
            c._process_response(spec, r, b"nope")


class TestDecodeBinary:
    def test_gzip_no_cap(self):
        c = _client()
        out = c._decode_binary("application/gzip", gzip.compress(b"payload"), 200)
        assert out == b"payload"

    def test_plain_media_passthrough(self):
        c = _client()
        assert c._decode_binary("application/octet-stream", b"raw", 200) == b"raw"

    def _zip(self, members: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for name, data in members.items():
                z.writestr(name, data)
        return buf.getvalue()

    def test_zip_single_member(self):
        c = _client()
        body = self._zip({"only.json": b"content"})
        assert c._decode_binary("application/zip", body, 200) == b"content"

    def test_zip_wrong_member_count_raises(self):
        c = _client()
        body = self._zip({"a": b"1", "b": b"2"})
        with pytest.raises(APIResponseValidationError):
            c._decode_binary("application/zip", body, 200)

    def test_zip_member_capped_ok(self):
        c = BaseClient(resolve_config(api_key=KEY, max_response_bytes=10_000_000))
        body = self._zip({"only": b"X" * 100})
        assert c._decode_binary("application/zip", body, 200) == b"X" * 100

    def test_zip_member_capped_raises(self):
        c = BaseClient(resolve_config(api_key=KEY, max_response_bytes=5))
        body = self._zip({"only": b"X" * 100})
        with pytest.raises(APIResponseValidationError):
            c._decode_binary("application/zip", body, 200)

    def test_gzip_inflate_capped_ok_and_over(self):
        big = b"A" * 400_000  # >_CAP_CHUNK once inflated -> exercises the tail loop
        payload = gzip.compress(big)
        ok = BaseClient(resolve_config(api_key=KEY, max_response_bytes=10_000_000))
        assert ok._decode_binary("application/gzip", payload, 200) == big
        over = BaseClient(resolve_config(api_key=KEY, max_response_bytes=1000))
        with pytest.raises(APIResponseValidationError):
            over._decode_binary("application/gzip", payload, 200)


class TestDecodeNdjsonAndCaps:
    def test_reject_declared_length(self):
        c = BaseClient(resolve_config(api_key=KEY, max_response_bytes=100))
        c._reject_declared_length(None, 200)  # None -> no-op
        c._reject_declared_length("not-an-int", 200)  # unparseable -> no-op
        c._reject_declared_length("50", 200)  # under cap -> no-op
        with pytest.raises(APIResponseValidationError):
            c._reject_declared_length("500", 200)

    def test_guard_cap(self):
        c = BaseClient(resolve_config(api_key=KEY, max_response_bytes=100))
        c._guard_cap(50, 200)  # under cap
        with pytest.raises(APIResponseValidationError):
            c._guard_cap(500, 200)


class TestBucketHeaderUpdate:
    def test_update_from_valid_header(self):
        c = _client()
        bucket = RateLimitBucket(rate=10.0)
        resp = httpx.Response(200, headers={"X-Vulners-Ratelimit-Reqlimit": "600"})
        c._update_bucket_from_headers(bucket, resp)
        assert bucket._rate == 10.0  # 600/60

    def test_missing_header_noop(self):
        c = _client()
        bucket = RateLimitBucket(rate=10.0)
        c._update_bucket_from_headers(bucket, httpx.Response(200))
        assert bucket._rate == 10.0

    def test_non_numeric_header_noop(self):
        c = _client()
        bucket = RateLimitBucket(rate=10.0)
        resp = httpx.Response(200, headers={"X-Vulners-Ratelimit-Reqlimit": "lots"})
        c._update_bucket_from_headers(bucket, resp)
        assert bucket._rate == 10.0

    def test_subminimal_rate_ignored(self):
        c = _client()
        bucket = RateLimitBucket(rate=10.0)
        resp = httpx.Response(200, headers={"X-Vulners-Ratelimit-Reqlimit": "0.5"})
        c._update_bucket_from_headers(bucket, resp)  # 0.5/60 < 1/60 -> ignored
        assert bucket._rate == 10.0


class TestRaiseStreamError:
    def test_json_body(self):
        c = _client()
        resp = httpx.Response(500, headers={"content-type": "application/json"})
        with pytest.raises(InternalServerError):
            c._raise_stream_error(resp, orjson.dumps({"error": "boom"}))

    def test_invalid_json_body(self):
        c = _client()
        resp = httpx.Response(500, headers={"content-type": "application/json"})
        with pytest.raises(APIStatusError):
            c._raise_stream_error(resp, b"<not json>")

    def test_non_json_body(self):
        c = _client()
        resp = httpx.Response(502, headers={"content-type": "text/html"})
        with pytest.raises(APIStatusError):
            c._raise_stream_error(resp, b"<html>bad gateway</html>")


# ---------------------------------------------------------------------------
# _retry
# ---------------------------------------------------------------------------


class TestRetryHelpers:
    def test_header_override(self):
        assert _header_override(None) is None
        assert _header_override(httpx.Headers({})) is None
        assert _header_override(httpx.Headers({"x-should-retry": "true"})) is True
        assert _header_override(httpx.Headers({"x-should-retry": "false"})) is False
        assert _header_override(httpx.Headers({"x-should-retry": "maybe"})) is None

    def test_should_retry_override_wins(self):
        info = ErrorInfo(status_code=200)
        assert _should_retry(info, httpx.Headers({"x-should-retry": "true"})) is True
        assert _should_retry(info, httpx.Headers({"x-should-retry": "false"})) is False

    def test_should_retry_by_status(self):
        assert _should_retry(ErrorInfo(status_code=500)) is True
        assert _should_retry(ErrorInfo(status_code=429)) is True
        assert _should_retry(ErrorInfo(status_code=400)) is False
        # a 200 with a non-retryable error code
        assert _should_retry(ErrorInfo(status_code=200, error_code=104)) is False

    def test_should_retry_exceptions(self):
        assert _should_retry(APIConnectionError()) is True
        assert _should_retry(ValueError("x")) is False

    def test_retry_after_seconds(self):
        assert _retry_after_seconds(None) is None
        assert _retry_after_seconds(httpx.Headers({"Retry-After": "3"})) == 3.0
        assert _retry_after_seconds(httpx.Headers({"retry-after-ms": "2500"})) == 2.5
        assert _retry_after_seconds(httpx.Headers({"retry-after-ms": "nope"})) is None
        assert _retry_after_seconds(httpx.Headers({"Retry-After": "999"})) is None  # > cap

    def test_retry_timeout(self):
        assert _retry_timeout(1, httpx.Headers({"Retry-After": "4"})) == 4.0
        # no hint -> exponential backoff with jitter in (0.375, 0.5] for attempt 1
        t = _retry_timeout(1)
        assert 0.0 < t <= 0.5
        # capped at 8s base for large attempts
        assert _retry_timeout(20) <= 8.0


# ---------------------------------------------------------------------------
# _response
# ---------------------------------------------------------------------------


def _httpx_response(status=200, content=b"body", ct="application/json") -> httpx.Response:
    req = httpx.Request("GET", "https://vulners.com/api/x")
    return httpx.Response(status, headers={"content-type": ct}, content=content, request=req)


class TestAPIResponse:
    def test_all_accessors(self):
        r = _httpx_response(content=b'{"a":1}')
        api = APIResponse(r, b'{"a":1}', {"a": 1}, parser=lambda v: v["a"])
        assert api.status_code == 200
        assert api.headers["content-type"] == "application/json"
        assert api.http_request.method == "GET"
        assert str(api.url).endswith("/api/x")
        assert api.content == b'{"a":1}'
        assert api.text == '{"a":1}'
        assert api.json() == {"a": 1}
        assert api.parse() == 1  # parser applied
        assert repr(api) == "<APIResponse [200]>"

    def test_json_empty_is_none_and_parse_without_parser(self):
        api = APIResponse(_httpx_response(content=b""), b"", {"x": 2})
        assert api.json() is None
        assert api.parse() == {"x": 2}

    def test_iter_bytes_and_lines(self):
        api = APIResponse(_httpx_response(), b"ab\ncd\nef", None)
        assert b"".join(api.iter_bytes(chunk_size=2)) == b"ab\ncd\nef"
        assert list(api.iter_lines()) == ["ab", "cd", "ef"]


class TestStreamedResponses:
    def test_sync_streamed(self):
        req = httpx.Request("GET", "https://vulners.com/x")
        resp = httpx.Response(
            200, headers={"content-type": "text/plain"}, content=b"a\nb", request=req
        )

        def parse(r: httpx.Response, content: bytes) -> Any:
            return content

        streamed = StreamedAPIResponse(resp, parse)
        assert streamed.status_code == 200
        assert streamed.headers["content-type"] == "text/plain"
        assert streamed.http_request.method == "GET"
        assert str(streamed.url).endswith("/x")
        assert list(streamed.iter_bytes()) == [b"a\nb"]
        assert streamed.read() == b"a\nb"
        assert streamed.read() == b"a\nb"  # cached
        assert streamed.parse() == b"a\nb"
        assert list(streamed.iter_lines()) == ["a", "b"]
        assert repr(streamed) == "<StreamedAPIResponse [200]>"
        streamed.close()

    def test_sync_streamed_iter_text(self):
        req = httpx.Request("GET", "https://vulners.com/x")
        resp = httpx.Response(200, content=b"hello", request=req)
        streamed = StreamedAPIResponse(resp, lambda r, c: c)
        assert "".join(streamed.iter_text()) == "hello"

    async def test_async_streamed(self):
        req = httpx.Request("GET", "https://vulners.com/x")
        resp = httpx.Response(
            200, headers={"content-type": "text/plain"}, content=b"x\ny", request=req
        )
        streamed: AsyncStreamedAPIResponse[Any] = AsyncStreamedAPIResponse(resp, lambda r, c: c)
        assert streamed.status_code == 200
        assert streamed.headers["content-type"] == "text/plain"
        assert streamed.http_request.method == "GET"
        assert str(streamed.url).endswith("/x")
        assert [chunk async for chunk in streamed.iter_bytes()] == [b"x\ny"]
        assert "".join([t async for t in streamed.iter_text()]) == "x\ny"
        assert await streamed.read() == b"x\ny"
        assert await streamed.read() == b"x\ny"  # cached
        assert await streamed.parse() == b"x\ny"
        assert repr(streamed) == "<AsyncStreamedAPIResponse [200]>"
        await streamed.close()


# ---------------------------------------------------------------------------
# _streaming
# ---------------------------------------------------------------------------


class TestStreamingDecoders:
    @staticmethod
    def _arr(*records: object) -> bytes:
        # Real archive shape: a pretty-printed JSON array, one element per line.
        return b"[\n" + b",\n".join(orjson.dumps(r) for r in records) + b"\n]"

    def test_plain_decoder_feed_and_flush(self):
        d = PlainJsonArrayDecoder()
        arr = self._arr({"a": 1}, {"b": 2})
        # split mid-array: the first feed yields the first element and leaves a
        # partial second element buffered inside the push parser.
        out = list(d.feed(arr[:12])) + list(d.feed(arr[12:]))
        out += list(d.flush())
        assert out == [{"a": 1}, {"b": 2}]

    def test_plain_decoder_cap(self):
        d = PlainJsonArrayDecoder(cap=3)
        with pytest.raises(APIResponseValidationError):
            list(d.feed(self._arr({"a": 1})))

    def test_gzip_decoder_no_cap(self):
        d = GzipJsonArrayDecoder()
        out = list(d.feed(gzip.compress(self._arr({"a": 1}, {"b": 2}))))
        out += list(d.flush())
        assert out == [{"a": 1}, {"b": 2}]

    def test_gzip_decoder_capped_ok_and_over(self):
        payload = gzip.compress(self._arr({"a": 1}, {"a": 1}, {"a": 1}))
        d_ok = GzipJsonArrayDecoder(cap=10_000)
        assert list(d_ok.feed(payload)) + list(d_ok.flush()) == [{"a": 1}] * 3
        d_over = GzipJsonArrayDecoder(cap=4)
        with pytest.raises(APIResponseValidationError):
            list(d_over.feed(payload))

    def test_make_decoder_and_is_zip(self):
        assert isinstance(make_array_decoder("application/gzip", None), GzipJsonArrayDecoder)
        assert isinstance(make_array_decoder("application/json", None), PlainJsonArrayDecoder)
        assert is_zip_media("application/zip") is True
        assert is_zip_media("application/json") is False

    def _zip(self, data: bytes) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("cve.json", data)
        return buf.getvalue()

    def test_iter_zip_json_array(self):
        body = self._zip(self._arr({"a": 1}, {"b": 2}))
        assert list(iter_zip_json_array(body)) == [{"a": 1}, {"b": 2}]

    def test_iter_zip_json_array_cap(self):
        body = self._zip(self._arr(*([{"a": 1}] * 100)))
        with pytest.raises(APIResponseValidationError):
            list(iter_zip_json_array(body, cap=5))


# ---------------------------------------------------------------------------
# _config
# ---------------------------------------------------------------------------


class TestConfig:
    def test_missing_key_raises(self, monkeypatch):
        monkeypatch.delenv("VULNERS_API_KEY", raising=False)
        with pytest.raises(VulnersError):
            resolve_config(api_key=None)

    def test_env_key(self, monkeypatch):
        monkeypatch.setenv("VULNERS_API_KEY", "ENV-KEY")
        cfg = resolve_config(api_key=None)
        assert cfg.api_key.get_secret_value() == "ENV-KEY"

    def test_empty_secretstr_falls_back_to_env(self, monkeypatch):
        monkeypatch.setenv("VULNERS_API_KEY", "ENV-KEY")
        cfg = resolve_config(api_key=SecretStr(""))
        assert cfg.api_key.get_secret_value() == "ENV-KEY"

    def test_secretstr_key_preserved(self):
        cfg = resolve_config(api_key=SecretStr("SECRET"))
        assert cfg.api_key.get_secret_value() == "SECRET"

    def test_base_url_from_env(self, monkeypatch):
        monkeypatch.setenv("VULNERS_BASE_URL", "https://example.test")
        cfg = resolve_config(api_key=KEY)
        assert str(cfg.base_url).startswith("https://example.test")

    def test_timeout_float_and_instance_and_retries(self):
        cfg = resolve_config(api_key=KEY, timeout=5.0, max_retries=7)
        assert cfg.timeout == httpx.Timeout(5.0)
        assert cfg.max_retries == 7
        t = httpx.Timeout(2.0)
        assert resolve_config(api_key=KEY, timeout=t).timeout is t

    def test_timeout_for_and_replace_and_repr(self):
        cfg = resolve_config(api_key=KEY)
        assert cfg.timeout_for("archive") == ARCHIVE_TIMEOUT
        assert cfg.timeout_for("default") == DEFAULT_TIMEOUT
        assert cfg.replace(max_retries=9).max_retries == 9
        assert KEY not in repr(cfg)
        assert "ClientConfig(" in repr(cfg)


# ---------------------------------------------------------------------------
# _logging
# ---------------------------------------------------------------------------


class TestLogging:
    def test_configure_from_env(self, monkeypatch):
        from vulners import _logging

        monkeypatch.setenv("VULNERS_LOG", "debug")
        _logging._configure_from_env()
        assert logger.level == logging.DEBUG

    def test_install_empty_secret_noop(self):
        before = len(logger.filters)
        install_key_redaction("")
        assert len(logger.filters) == before

    def test_install_is_idempotent(self):
        install_key_redaction("DEDUP-SECRET")
        n = len(logger.filters)
        install_key_redaction("DEDUP-SECRET")
        assert len(logger.filters) == n

    def test_filter_redacts_msg_and_args(self):
        filt = _SecretRedactingFilter("TOPSECRET")
        rec = logging.LogRecord("vulners", logging.INFO, __file__, 1, "key=TOPSECRET", None, None)
        assert filt.filter(rec) is True
        assert "TOPSECRET" not in rec.msg
        rec2 = logging.LogRecord(
            "vulners", logging.INFO, __file__, 1, "x %s %s", ("TOPSECRET", 5), None
        )
        filt.filter(rec2)
        assert rec2.args[0] == "[REDACTED]"
        assert rec2.args[1] == 5

    def test_filter_non_tuple_args(self):
        filt = _SecretRedactingFilter("SEK")
        rec = logging.LogRecord("vulners", logging.INFO, __file__, 1, "x %s", ("SEK",), None)
        # a mapping-style single arg (record.args set to a dict) hits the non-tuple path
        rec.args = {"k": "SEK"}  # type: ignore[assignment]
        assert filt.filter(rec) is True


# ---------------------------------------------------------------------------
# _exceptions extra branches
# ---------------------------------------------------------------------------


class TestExceptionsExtra:
    def test_parse_retry_after_naive_httpdate(self):
        # An HTTP-date without an explicit zone is treated as UTC.
        assert _parse_retry_after("Wed, 21 Oct 2099 07:28:00") > 0

    def test_extract_message_non_dict(self):
        assert _extract_message(123) == (None, None)

    def test_extract_message_error_items_without_loc(self):
        code, msg = _extract_message({"errors": [{"msg": "bad"}, "skipme"]})
        assert code is None and msg == "bad"

    def test_extract_message_empty_items(self):
        assert _extract_message({"errors": [1, 2]}) == (None, None)

    def test_has_error_markers(self):
        assert _has_error_markers("string") is False
        assert _has_error_markers(123) is False
        assert _has_error_markers({"result": "error"}) is True
        assert _has_error_markers({"data": {"error": "x"}}) is True
        assert _has_error_markers({"error": "x"}) is True
        assert _has_error_markers({"detail": [{"msg": "x"}]}) is True
        assert _has_error_markers({"ok": 1}) is False

    def test_extract_error_headers_none(self):
        info = _extract_error(500, None, {"error": "boom"})
        assert info is not None and info.retry_after is None

    def test_status_class_none_and_409(self):
        assert _status_class(None) is APIStatusError
        assert _status_class(409) is ConflictError
        assert _status_class(499) is APIStatusError

    def test_make_error_status_none(self):
        err = _make_error(ErrorInfo(status_code=None))
        assert type(err) is APIStatusError

    def test_error_info_repr(self):
        r = repr(ErrorInfo(status_code=404, error_code="X", message="m"))
        assert "ErrorInfo(status_code=404" in r

    def test_rate_limit_error_carries_retry_after(self):
        err = _make_error(ErrorInfo(status_code=429, retry_after=5.0))
        assert isinstance(err, RateLimitError)
        assert err.retry_after == 5.0


# ---------------------------------------------------------------------------
# _models/_base extra branches
# ---------------------------------------------------------------------------


class _Inner(VulnersModel):
    x: int | None = None


class _Outer(VulnersModel):
    inner: _Inner | None = None
    items: list[_Inner] | None = None
    mapping: dict[str, _Inner] | None = None
    annotated: Annotated[_Inner | None, Field(default=None)] = None
    by_name: int | None = Field(default=None, alias="byNameAlias")


class TestConstructType:
    def test_none_type_returns_value(self):
        assert construct_type({"a": 1}, None) == {"a": 1}

    def test_annotated_stripped(self):
        out = construct_type({"annotated": {"x": 1}}, _Outer)
        assert isinstance(out.annotated, _Inner)
        assert out.annotated.x == 1

    def test_list_with_non_list_value_passes_through(self):
        out = construct_type("scalar", list[_Inner])
        assert out == "scalar"

    def test_dict_of_models(self):
        out = construct_type({"mapping": {"k": {"x": 2}}}, _Outer)
        assert isinstance(out.mapping["k"], _Inner)

    def test_dict_origin_non_mapping_passes_through(self):
        assert construct_type("scalar", dict[str, _Inner]) == "scalar"

    def test_value_already_model_instance(self):
        inner = _Inner(x=5)
        assert construct_type(inner, _Inner) is inner

    def test_field_present_by_name_not_alias(self):
        out = construct_type({"byNameAlias": 1}, _Outer)
        assert out.by_name == 1
        out2 = construct_type({"by_name": 2}, _Outer)  # python name also accepted
        assert out2.by_name == 2

    def test_union_first_member_non_mapping(self):
        # a plain (typing) union with an int value -> first member.
        assert construct_type(7, int | str) == 7

    def test_optional_with_no_members(self):
        # an optional with a non-None value: value returned unchanged.
        assert construct_type(3, int | None) == 3

    def test_discriminator_resolves_subclass(self):
        class Base(VulnersModel):
            kind: str | None = None

        class Special(Base):
            extra: int | None = None

        register_discriminator(Base, "kind", {"special": Special})
        out = construct_type({"kind": "special", "extra": 9}, Base)
        assert isinstance(out, Special)
        # unknown tag falls back to base
        out2 = construct_type({"kind": "other"}, Base)
        assert type(out2) is Base

    def test_discriminator_object(self):
        disc = Discriminator("t", {"a": _Inner}, _Outer)
        assert disc.resolve({"t": "a"}) is _Inner
        assert disc.resolve({"t": "missing"}) is _Outer


# ---------------------------------------------------------------------------
# _pagination extra
# ---------------------------------------------------------------------------


class TestPaginationContainers:
    def test_search_page_getitem_repr_and_no_fetch_runtime_error(self):
        page = SearchPage(data=[1, 2, 3], total=1_000_000, offset=0, limit=3)
        assert page[0] == 1
        assert "SearchPage(total=1000000" in repr(page)
        # within the window but no fetch callback -> RuntimeError
        with pytest.raises(RuntimeError):
            page.next_page()

    async def test_async_search_page_getitem_len_repr_and_runtime_error(self):
        page: AsyncSearchPage[int] = AsyncSearchPage(
            data=[1, 2], total=1_000_000, offset=0, limit=2
        )
        assert page[0] == 1
        assert len(page) == 2
        assert "AsyncSearchPage(total=1000000" in repr(page)
        with pytest.raises(RuntimeError):
            await page.next_page()


# ---------------------------------------------------------------------------
# rate-limit buckets: update + zero-rate consume
# ---------------------------------------------------------------------------


class TestBucketExtra:
    def test_sync_update_valid_and_zero_rate_consume(self):
        b = RateLimitBucket(rate=10.0)
        b.update(rate=5.0, burst=1.0)
        assert b._rate == 5.0
        zero = RateLimitBucket(rate=0.0)
        zero.consume()  # rate not > 0 -> returns immediately

    async def test_async_update_valid_and_zero_rate_consume(self):
        b = AsyncRateLimitBucket(rate=10.0)
        b.update(rate=5.0)
        assert b._rate == 5.0
        zero = AsyncRateLimitBucket(rate=0.0)
        await zero.consume()


# ---------------------------------------------------------------------------
# _types sentinels
# ---------------------------------------------------------------------------


class TestSentinels:
    def test_reprs_and_bools(self):
        assert repr(not_given) == "NOT_GIVEN"
        assert repr(omit) == "omit"
        assert bool(NotGiven()) is False
        assert bool(Omit()) is False
