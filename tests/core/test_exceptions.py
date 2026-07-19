"""Error normalization matrix for the v4 core exception layer.

All data is synthetic (fake keys, fake CVE ids). Only response *shapes* mirror
the real server envelopes.
"""

from __future__ import annotations

import httpx
import pytest

from vulners._exceptions import (
    APIStatusError,
    AuthenticationError,
    BadRequestError,
    InternalServerError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    UnprocessableEntityError,
    _extract_error,
    _make_error,
    _parse_retry_after,
    _redact_secret,
)


def _headers(**kw: str) -> httpx.Headers:
    return httpx.Headers(kw)


class TestExtractError:
    def test_v3_error_in_http_200(self):
        # A malformed v3 parameter returns an error envelope with HTTP 200.
        body = {"result": "error", "data": {"error": "bad param", "errorCode": 104}}
        info = _extract_error(200, _headers(), body)
        assert info is not None
        assert info.status_code == 200
        assert info.error_code == 104
        assert "bad param" in info.message
        # errorCode-first mapping wins over the (200) status fallback.
        assert isinstance(_make_error(info), BadRequestError)

    def test_v4_validation_400_is_bad_request_and_redacts_input(self):
        body = {
            "errors": [
                {
                    "loc": ["body", "query"],
                    "msg": "field required",
                    "type": "missing",
                    "input": {"apiKey": "SYNTHETIC-SECRET"},
                }
            ]
        }
        info = _extract_error(400, _headers(), body, secret="SYNTHETIC-SECRET")
        assert info is not None
        assert "field required at body.query" in info.message
        err = _make_error(info)
        assert isinstance(err, BadRequestError)
        # The echoed request input is redacted in the stored payload.
        assert info.data["errors"][0]["input"]["apiKey"] == "[REDACTED]"

    def test_fastapi_detail_422(self):
        body = {"detail": [{"loc": ["q"], "msg": "invalid"}]}
        info = _extract_error(422, _headers(), body)
        assert info is not None
        assert isinstance(_make_error(info), UnprocessableEntityError)

    def test_404_without_error_code(self):
        info = _extract_error(404, _headers(), {"data": {"error": "not found"}})
        assert info is not None
        assert info.error_code is None
        assert isinstance(_make_error(info), NotFoundError)

    def test_bare_5xx_non_dict_body(self):
        info = _extract_error(503, _headers(), "<html>Service Unavailable</html>")
        assert info is not None
        assert info.message == "<html>Service Unavailable</html>"
        assert isinstance(_make_error(info), InternalServerError)

    def test_403_html_no_key(self):
        # Cloudflare "Just a moment" page when the key is missing.
        info = _extract_error(403, _headers(), "Just a moment...")
        assert info is not None
        assert isinstance(_make_error(info), PermissionDeniedError)

    def test_401_is_authentication_error(self):
        info = _extract_error(401, _headers(), {"error": "unauthorized"})
        assert isinstance(_make_error(info), AuthenticationError)

    def test_clean_200_envelope_is_not_an_error(self):
        assert _extract_error(200, _headers(), {"result": "OK", "data": {"x": 1}}) is None

    def test_clean_200_list_is_not_an_error(self):
        assert _extract_error(200, _headers(), [1, 2, 3]) is None

    def test_429_carries_retry_after(self):
        info = _extract_error(429, _headers(**{"Retry-After": "7"}), {"error": "slow down"})
        assert info is not None
        assert info.retry_after == 7.0
        err = _make_error(info)
        assert isinstance(err, RateLimitError)
        assert err.retry_after == 7.0

    def test_unknown_4xx_falls_back_to_apistatuserror(self):
        info = _extract_error(418, _headers(), {"error": "teapot"})
        err = _make_error(info)
        assert isinstance(err, APIStatusError)
        assert err.status_code == 418


class TestRetryAfter:
    def test_numeric_seconds(self):
        assert _parse_retry_after("5") == 5.0

    def test_http_date(self):
        # A far-future HTTP-date parses to a positive delay.
        assert _parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT") > 0

    def test_past_date_collapses_to_zero(self):
        assert _parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0

    def test_garbage_is_none(self):
        assert _parse_retry_after("not-a-date") is None

    def test_empty_is_none(self):
        assert _parse_retry_after(None) is None
        assert _parse_retry_after("") is None

    @pytest.mark.parametrize("bad", ["-1", "nan", "inf"])
    def test_non_finite_or_negative_is_none(self, bad):
        assert _parse_retry_after(bad) is None


class TestRedaction:
    def test_masks_apikey_field(self):
        out = _redact_secret({"apiKey": "SECRET", "q": "keep"})
        assert out == {"apiKey": "[REDACTED]", "q": "keep"}

    def test_masks_secret_value_in_strings(self):
        out = _redact_secret({"msg": "failed for key SECRET"}, secret="SECRET")
        assert out == {"msg": "failed for key [REDACTED]"}

    def test_payload_without_secret_is_unchanged(self):
        payload = {"error": "boom", "errorCode": 104}
        assert _redact_secret(payload) == payload
