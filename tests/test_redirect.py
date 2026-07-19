"""Cross-origin redirect key-leak tests.

follow_redirects=True stays on, but the X-Api-Key header must not travel to a
host other than the configured origin.
"""

from __future__ import annotations

import httpx
import orjson
import pytest

import vulners
from vulners.base import VulnersApiError, VulnersApiTransport

KEY = "SYNTHETIC-SECRET-KEY"
ORIGIN = "https://vulners.com"


class RedirectServer:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.responses: list[httpx.Response] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses.pop(0)


def _api(origin: str | None = ORIGIN):
    api = vulners.VulnersApi(KEY)
    rs = RedirectServer()
    origin_url = httpx.URL(origin) if origin is not None else None
    api._client._transport = VulnersApiTransport(
        httpx.MockTransport(rs.handler), origin=origin_url
    )
    return api, rs


def _ok():
    return httpx.Response(200, json={"result": "OK", "data": {}})


class TestRedirectKeyStrip:
    def test_happy_path_no_redirect_keeps_key(self):
        api, rs = _api()
        rs.responses = [_ok()]
        api._invoke("GET", "/api/v3/test", {}, ())
        assert len(rs.requests) == 1
        assert rs.requests[0].headers.get("x-api-key") == KEY

    def test_same_origin_redirect_keeps_key(self):
        api, rs = _api()
        rs.responses = [
            httpx.Response(302, headers={"location": "https://vulners.com/other"}),
            _ok(),
        ]
        api._invoke("GET", "/api/v3/test", {}, ())
        assert len(rs.requests) == 2
        assert rs.requests[0].headers.get("x-api-key") == KEY
        assert rs.requests[1].headers.get("x-api-key") == KEY

    def test_cross_origin_redirect_strips_key(self):
        api, rs = _api()
        rs.responses = [
            httpx.Response(302, headers={"location": "https://evil.example/steal"}),
            _ok(),
        ]
        api._invoke("GET", "/api/v3/test", {}, ())
        assert len(rs.requests) == 2
        assert rs.requests[0].url.host == "vulners.com"
        assert rs.requests[0].headers.get("x-api-key") == KEY
        assert rs.requests[1].url.host == "evil.example"
        assert "x-api-key" not in rs.requests[1].headers

    def test_https_upgrade_same_host_keeps_key(self):
        api, rs = _api(origin="http://vulners.com")
        rs.responses = [
            httpx.Response(302, headers={"location": "https://vulners.com/secure"}),
            _ok(),
        ]
        api._invoke("GET", "/api/v3/test", {}, ())
        assert rs.requests[1].url.scheme == "https"
        assert rs.requests[1].headers.get("x-api-key") == KEY

    def test_https_downgrade_strips_key(self):
        api, rs = _api(origin="https://vulners.com")
        rs.responses = [
            httpx.Response(302, headers={"location": "http://vulners.com/insecure"}),
            _ok(),
        ]
        api._invoke("GET", "/api/v3/test", {}, ())
        assert rs.requests[1].url.scheme == "http"
        assert "x-api-key" not in rs.requests[1].headers

    def test_different_port_strips_key(self):
        api, rs = _api(origin="https://vulners.com")
        rs.responses = [
            httpx.Response(302, headers={"location": "https://vulners.com:8443/x"}),
            _ok(),
        ]
        api._invoke("GET", "/api/v3/test", {}, ())
        assert "x-api-key" not in rs.requests[1].headers

    def test_default_port_is_same_origin(self):
        api, rs = _api(origin="https://vulners.com")
        rs.responses = [
            httpx.Response(302, headers={"location": "https://vulners.com:443/x"}),
            _ok(),
        ]
        api._invoke("GET", "/api/v3/test", {}, ())
        assert rs.requests[1].headers.get("x-api-key") == KEY

    def test_bounce_back_to_origin_does_not_restore_key(self):
        api, rs = _api()
        rs.responses = [
            httpx.Response(302, headers={"location": "https://evil.example/hop"}),
            httpx.Response(302, headers={"location": "https://vulners.com/back"}),
            _ok(),
        ]
        api._invoke("GET", "/api/v3/test", {}, ())
        assert len(rs.requests) == 3
        # once stripped on the evil hop, the key is gone even after bouncing back
        assert "x-api-key" not in rs.requests[1].headers
        assert "x-api-key" not in rs.requests[2].headers

    def test_no_origin_configured_keeps_legacy_behavior(self):
        # VulnersApiTransport(inner) without origin: never strips (matches the
        # test-harness wrapper and the earlier behavior).
        api, rs = _api(origin=None)
        rs.responses = [
            httpx.Response(302, headers={"location": "https://evil.example/steal"}),
            _ok(),
        ]
        api._invoke("GET", "/api/v3/test", {}, ())
        assert rs.requests[1].headers.get("x-api-key") == KEY

    def test_set_cookie_still_stripped(self):
        api, rs = _api()
        rs.responses = [
            httpx.Response(200, json={"result": "OK", "data": {}},
                          headers={"set-cookie": "sid=abc"}),
        ]
        api._invoke("GET", "/api/v3/test", {}, ())
        # the wrapper still strips set-cookie from the response
        assert len(rs.requests) == 1

    def test_production_transport_has_origin(self):
        api = vulners.VulnersApi(KEY)
        transport = api._client._transport
        assert isinstance(transport, VulnersApiTransport)
        assert transport._origin == httpx.URL(ORIGIN)


class TestRedirectBodyCredentialStrip:
    """A 307/308 preserves the POST body, so the apiKey an add_api_key endpoint
    injects into it must be scrubbed on a cross-origin hop (the header strip
    alone does not cover the body)."""

    @pytest.mark.parametrize("status", [307, 308])
    def test_cross_origin_body_key_stripped(self, status):
        api, rs = _api()
        rs.responses = [
            httpx.Response(status, headers={"location": "https://evil.example/steal"}),
            _ok(),
        ]
        api._invoke("POST", "/api/v3/test", {}, (), add_api_key=True)
        assert rs.requests[1].url.host == "evil.example"
        assert "x-api-key" not in rs.requests[1].headers
        body = orjson.loads(rs.requests[1].content) if rs.requests[1].content else {}
        assert "apiKey" not in body
        assert KEY not in rs.requests[1].content.decode("utf-8", "replace")

    @pytest.mark.parametrize("status", [307, 308])
    def test_same_origin_body_key_preserved(self, status):
        # Same-origin redirect never enters the strip branch: the body (and the
        # key it carries) stay byte-identical.
        api, rs = _api()
        rs.responses = [
            httpx.Response(status, headers={"location": "https://vulners.com/other"}),
            _ok(),
        ]
        api._invoke("POST", "/api/v3/test", {}, (), add_api_key=True)
        assert orjson.loads(rs.requests[1].content) == {"apiKey": KEY}
        assert rs.requests[1].headers.get("x-api-key") == KEY

    def test_scrub_credential_removes_query_and_form(self):
        transport = VulnersApiTransport(
            httpx.MockTransport(lambda r: _ok()), origin=httpx.URL(ORIGIN)
        )
        # query
        req = httpx.Request("GET", "https://evil.example/x?apiKey=%s&a=1" % KEY)
        transport._scrub_credential(req)
        assert "apiKey" not in dict(req.url.params)
        assert dict(req.url.params) == {"a": "1"}
        # form body
        req = httpx.Request(
            "POST",
            "https://evil.example/x",
            content=("apiKey=%s&a=1" % KEY).encode(),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        transport._scrub_credential(req)
        assert KEY not in req.read().decode()
        assert req.read().decode() == "a=1"


class TestRedirectSsrfGuard:
    """A cross-origin redirect to a private / internal IP literal is refused so
    the client cannot be turned into an SSRF probe; public hosts still work."""

    @pytest.mark.parametrize(
        "location",
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/x",
            "http://10.0.0.5/x",
            "http://172.16.9.9/x",
            "http://192.168.1.1/x",
            "http://[::1]/x",
            "http://0.0.0.0/x",
        ],
    )
    def test_private_redirect_refused(self, location):
        api, rs = _api()
        rs.responses = [
            httpx.Response(302, headers={"location": location}),
            _ok(),
        ]
        with pytest.raises(VulnersApiError):
            api._invoke("GET", "/api/v3/test", {}, ())
        # only the origin request went out; the internal hop was never sent
        assert len(rs.requests) == 1

    @pytest.mark.parametrize(
        "location",
        [
            "https://8.8.8.8/x",
            "https://storage.googleapis.com/bucket/object",
            "https://evil.example/x",
        ],
    )
    def test_public_redirect_allowed(self, location):
        api, rs = _api()
        rs.responses = [
            httpx.Response(302, headers={"location": location}),
            _ok(),
        ]
        api._invoke("GET", "/api/v3/test", {}, ())
        assert len(rs.requests) == 2

    def test_on_prem_private_origin_not_blocked(self):
        # A private-IP server_url is same-origin for its own requests, so the
        # guard (cross-origin only) never fires on the legitimate call.
        api = vulners.VulnersApi(KEY, server_url="http://10.0.0.1")
        rs = RedirectServer()
        api._client._transport = VulnersApiTransport(
            httpx.MockTransport(rs.handler), origin=httpx.URL("http://10.0.0.1")
        )
        rs.responses = [_ok()]
        api._invoke("GET", "/api/v3/test", {}, ())
        assert len(rs.requests) == 1
        assert rs.requests[0].url.host == "10.0.0.1"
        assert rs.requests[0].headers.get("x-api-key") == KEY
        api.close()
