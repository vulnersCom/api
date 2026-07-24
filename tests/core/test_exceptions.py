"""Error normalization matrix for the v4 core exception layer.

All data is synthetic (fake keys, fake CVE ids). Only response *shapes* mirror
the real server envelopes.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from vulners._client import Vulners
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

    def test_scope_violation_158_in_http_200_is_permission_denied(self):
        # "Api key scope violation" arrives in a v3 envelope with HTTP 200; the
        # errorCode-first mapping must classify it as a permission denial, not a
        # generic APIStatusError from the (200) status fallback.
        body = {
            "result": "error",
            "data": {"error": "Api key scope violation", "errorCode": 158},
        }
        info = _extract_error(200, _headers(), body)
        assert info is not None
        assert info.status_code == 200
        assert info.error_code == 158
        assert isinstance(_make_error(info), PermissionDeniedError)

    def test_scope_violation_158_on_403_is_permission_denied(self):
        # Same code delivered on an HTTP 403 also maps to PermissionDeniedError
        # (which is the 403 status class too, so the mapping is consistent).
        body = {"result": "error", "data": {"error": "Api key scope violation", "errorCode": 158}}
        info = _extract_error(403, _headers(), body)
        assert info is not None
        assert info.status_code == 403
        assert info.error_code == 158
        assert isinstance(_make_error(info), PermissionDeniedError)

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


_SCOPE_KEY = "SYNTHETIC-TEST-KEY"
_SCOPE_SEARCH_URL = "https://vulners.com/api/v3/search/lucene/"
_SCOPE_ENVELOPE = {
    "result": "error",
    "data": {"error": "Api key scope violation", "errorCode": 158},
}


class TestScopeViolationEndToEnd:
    """errorCode 158 (scope violation) reaches the caller as PermissionDeniedError."""

    @respx.mock
    def test_http_200_error_body_raises_permission_denied(self):
        # The server returns the scope violation in a v3 envelope with HTTP 200.
        route = respx.post(_SCOPE_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_SCOPE_ENVELOPE)
        )
        with Vulners(_SCOPE_KEY) as client:
            with pytest.raises(PermissionDeniedError) as excinfo:
                client.search.query("ssh")
        # A permission error is terminal: no retries.
        assert route.call_count == 1
        assert excinfo.value.error_code == 158
        assert excinfo.value.status_code == 200

    @respx.mock
    def test_http_403_error_body_raises_permission_denied(self):
        route = respx.post(_SCOPE_SEARCH_URL).mock(
            return_value=httpx.Response(403, json=_SCOPE_ENVELOPE)
        )
        with Vulners(_SCOPE_KEY) as client:
            with pytest.raises(PermissionDeniedError) as excinfo:
                client.search.query("ssh")
        assert route.call_count == 1
        assert excinfo.value.error_code == 158
        assert excinfo.value.status_code == 403

    @respx.mock
    def test_scope_violation_still_catchable_as_legacy_vulners_api_error(self):
        # The v3-era co-hierarchy is preserved: a PermissionDeniedError is still a
        # VulnersApiError, so migrating handlers keep catching it (BC unchanged).
        from vulners.base import VulnersApiError

        respx.post(_SCOPE_SEARCH_URL).mock(return_value=httpx.Response(200, json=_SCOPE_ENVELOPE))
        with Vulners(_SCOPE_KEY) as client:
            with pytest.raises(VulnersApiError) as excinfo:
                client.search.query("ssh")
        assert isinstance(excinfo.value, PermissionDeniedError)
        assert excinfo.value.error_code == 158


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


class TestLegacyCoHierarchy:
    """Server-reported v4 errors stay catchable by v3-era handlers (and only they)."""

    def test_api_error_is_caught_as_vulners_api_error(self):
        from vulners._exceptions import APIError, NotFoundError
        from vulners.base import VulnersApiError

        for exc in (APIError("boom"), NotFoundError("gone", status_code=404)):
            with pytest.raises(VulnersApiError):
                raise exc

    def test_transport_errors_are_not_vulners_api_error(self):
        from vulners._exceptions import (
            APIConnectionError,
            APIResponseValidationError,
            APITimeoutError,
        )
        from vulners.base import VulnersApiError

        for exc in (
            APIConnectionError(),
            APITimeoutError(),
            APIResponseValidationError("bad", status_code=200, data="x"),
        ):
            assert not isinstance(exc, VulnersApiError)

    def test_v3_attribute_spellings(self):
        from vulners._exceptions import APIError

        err = APIError("boom", status_code=500, data={"error": "x"})
        assert err.http_status == 500
        assert err.body == {"error": "x"}

    def test_plan_name_aliases(self):
        from vulners._exceptions import (
            InternalServerError,
            ServerError,
            UnprocessableEntityError,
            ValidationError,
        )

        assert ValidationError is UnprocessableEntityError
        assert ServerError is InternalServerError


class TestErrorInfoEnrichment:
    def test_request_id_from_headers(self):
        import httpx

        from vulners._exceptions import _extract_error, _make_error

        info = _extract_error(
            500,
            httpx.Headers({"X-Request-Id": "req-42"}),
            {"result": "error", "data": {"error": "boom", "errorCode": 1}},
        )
        assert info is not None and info.request_id == "req-42"
        assert _make_error(info).request_id == "req-42"

    def test_validation_errors_structured_without_input_echo(self):
        import httpx

        from vulners._exceptions import _extract_error, _make_error

        body = {
            "errors": [
                {"type": "missing", "loc": ["body", "query"], "msg": "req", "input": {"k": "S"}},
                "not-a-dict",
            ]
        }
        info = _extract_error(400, httpx.Headers(), body, secret="S")
        assert info is not None
        assert info.validation_errors == (
            {"type": "missing", "loc": ["body", "query"], "msg": "req"},
        )
        err = _make_error(info)
        assert err.validation_errors == [
            {"type": "missing", "loc": ["body", "query"], "msg": "req"}
        ]

    def test_validation_items_absent_for_v3_envelope(self):
        import httpx

        from vulners._exceptions import _extract_error

        info = _extract_error(
            200, httpx.Headers(), {"result": "error", "data": {"error": "e", "errorCode": 104}}
        )
        assert info is not None and info.validation_errors == ()

    def test_validation_items_non_dict_body(self):
        from vulners._exceptions import _validation_items

        assert _validation_items("nope", None) == ()
        assert _validation_items({"errors": "not-a-list"}, None) == ()
