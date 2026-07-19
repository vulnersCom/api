"""The API key must never leak through an exception's text or a header repr.

All keys here are synthetic. These cover the error-payload scrub (a server echo
of the credential must not reach str()/repr()) and the header-repr masking.
"""

from __future__ import annotations

import httpx
import pytest

import vulners
from vulners.base import VulnersApiError

SECRET = "SYNTHETIC-TEST-KEY-0000000000"


class TestApiErrorScrub:
    def test_apikey_field_is_masked(self):
        exc = VulnersApiError(400, {"apiKey": SECRET, "error": "bad request"})
        assert SECRET not in str(exc)
        assert SECRET not in repr(exc)
        # str() surfaces the clean server message
        assert exc.message == "bad request"
        # the apiKey field is masked in the preserved payload
        assert SECRET not in str(exc.data)
        assert "[REDACTED]" in str(exc.data)
        assert exc.data["error"] == "bad request"

    def test_x_api_key_field_is_masked(self):
        exc = VulnersApiError(400, {"headers": {"X-Api-Key": SECRET}})
        assert SECRET not in str(exc)
        assert SECRET not in repr(exc)

    def test_ordinary_payload_preserved_and_parsed(self):
        # No key material -> the payload is preserved verbatim on .data and the
        # human message / error code are parsed out for convenient access.
        data = {"error": "Synthetic error message", "errorCode": 104}
        exc = VulnersApiError(200, data)
        assert exc.data == data
        assert exc.error_code == 104
        assert exc.message == "Synthetic error message (errorCode 104)"
        assert str(exc) == "Synthetic error message (errorCode 104)"

    def test_string_payload_without_key_unchanged(self):
        exc = VulnersApiError(502, "502 Bad Gateway")
        assert exc.args[0] == "502 Bad Gateway"

    def test_server_error_echo_of_key_is_scrubbed(self, api, server):
        # The server rejects a request and echoes the submitted body, including
        # the injected apiKey, in the error envelope.
        server.enqueue_envelope(
            {"error": "validation failed", "apiKey": api._api_key},
            result="error",
        )
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("POST", "/synthetic/echo", {}, (), add_api_key=True)
        assert api._api_key not in str(excinfo.value)
        assert api._api_key not in repr(excinfo.value)

    def test_literal_key_in_plain_error_body_is_scrubbed(self, api, server):
        body = ("gateway error for key " + api._api_key).encode()
        server.enqueue_raw(body, "text/plain", status_code=500)
        with pytest.raises(VulnersApiError) as excinfo:
            api._invoke("GET", "/synthetic/plain", {}, ())
        assert api._api_key not in str(excinfo.value)


class TestHeaderReprMasking:
    def test_x_api_key_masked_in_headers_repr(self):
        req = httpx.Request("GET", "https://vulners.com/x", headers={"X-Api-Key": SECRET})
        assert SECRET not in repr(req.headers)
        assert "[secure]" in repr(req.headers)
        # the value is still readable through the normal accessors and on wire
        assert req.headers["x-api-key"] == SECRET

    def test_key_not_in_client_or_transport_repr(self):
        api = vulners.VulnersApi(SECRET)
        try:
            assert SECRET not in repr(api._client)
            assert SECRET not in repr(api._client._transport)
            assert SECRET not in repr(api)
        finally:
            api.close()
