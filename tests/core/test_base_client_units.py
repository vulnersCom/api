"""Direct unit tests for the sans-IO helpers on the v4 BaseClient.

Request building, response decoding, binary/JSON-array decode and response
caps, rate-limit header updates, and stream-error raising. Split out of
test_core_units.py so the base-client block is its own file. Synthetic data
throughout (fake keys/ids); only response shapes are realistic."""

from __future__ import annotations

import gzip
import io
import zipfile

import httpx
import orjson
import pytest

from vulners._base_client import (
    BaseClient,
    RequestSpec,
    _clean_params,
    _is_proxy_auth_error,
    _redact_proxy,
)
from vulners._config import (
    ARCHIVE_TIMEOUT,
    DEFAULT_TIMEOUT,
    resolve_config,
)
from vulners._exceptions import (
    APIResponseValidationError,
    APIStatusError,
    BadRequestError,
    InternalServerError,
)
from vulners._ratelimit import RateLimitBucket
from vulners._types import not_given, omit

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

    def test_unwrap_missing_required_key_raises(self):
        # A required envelope key that is absent is a contract violation, surfaced
        # as APIResponseValidationError rather than silently returning the wrong shape.
        c = _client()
        spec = RequestSpec("POST", "/x", unwrap=("data", "missing"))
        body = b'{"data":{"x":1}}'
        with pytest.raises(APIResponseValidationError):
            c._process_response(spec, self._resp(content=body), body)

    def test_unwrap_optional_missing_key_returns_current(self):
        # unwrap_optional keeps the best-effort break for a genuinely optional key.
        c = _client()
        spec = RequestSpec("POST", "/x", unwrap=("data", "missing"), unwrap_optional=True)
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

    def test_problem_json_media_is_parsed(self):
        # application/problem+json and other vendor "+json" types are parsed as JSON,
        # not handed back as opaque bytes — a 200 body unwraps normally.
        c = _client()
        spec = RequestSpec("GET", "/x", unwrap=("data",))
        body = b'{"data":{"ok":1}}'
        r = self._resp(ct="application/problem+json", content=body)
        assert c._process_response(spec, r, body) == {"ok": 1}

    def test_problem_json_error_status_raises_typed(self):
        # A 4xx "+json" error body still becomes a typed status error.
        c = _client()
        spec = RequestSpec("GET", "/x")
        body = b'{"error":"nope"}'
        r = self._resp(status=404, ct="application/vnd.api+json", content=body)
        with pytest.raises(APIStatusError):
            c._process_response(spec, r, body)

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


class TestRedactProxy:
    def test_str_proxy_with_port(self):
        assert _redact_proxy("http://proxy.local:3128") == "http://proxy.local:3128"

    def test_str_proxy_without_port(self):
        # No explicit port -> host only, no trailing colon.
        assert _redact_proxy("http://proxy.local") == "http://proxy.local"

    def test_credentials_are_stripped(self):
        # A proxy password must never reach a message/log via the redacted form.
        redacted = _redact_proxy("http://user:secret@proxy.local:3128")
        assert redacted == "http://proxy.local:3128"
        assert "user" not in redacted
        assert "secret" not in redacted

    def test_httpx_proxy_instance(self):
        proxy = httpx.Proxy("http://user:secret@proxy.local:8080")
        assert _redact_proxy(proxy) == "http://proxy.local:8080"


class TestIsProxyAuthError:
    def test_407_proxy_error_is_terminal(self):
        assert _is_proxy_auth_error(httpx.ProxyError("407 Proxy Authentication Required"))

    def test_non_407_proxy_error_is_not(self):
        # A 502 from the proxy is not the terminal auth case; still retryable.
        assert not _is_proxy_auth_error(httpx.ProxyError("502 Bad Gateway"))

    def test_non_proxy_error_is_not(self):
        assert not _is_proxy_auth_error(httpx.ConnectError("refused"))


class TestConnectionErrorMessage:
    def test_names_proxy_when_configured(self):
        c = _client()
        c._proxy = "http://user:secret@proxy.local:3128"
        message = c._connection_error_message(httpx.ConnectError("refused"))
        assert message == "Connection error: refused (proxy http://proxy.local:3128)"
        assert "secret" not in message

    def test_plain_when_no_proxy(self):
        c = _client()
        assert c._proxy is None
        assert c._connection_error_message(httpx.ConnectError("refused")) == (
            "Connection error: refused"
        )


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
