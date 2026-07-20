"""Credential-safety policy enforced by the transport wrappers."""

from __future__ import annotations

import httpx
import orjson
import pytest

from vulners._exceptions import APIConnectionError
from vulners._transport import (
    AsyncVulnersTransport,
    VulnersTransport,
    _guard_redirect_target,
    _host_as_ip,
)

ORIGIN = httpx.URL("https://vulners.com")


def _recording_inner(records: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        request.read()  # materialize the body as delivered
        records.append(request)
        return httpx.Response(
            200, content=orjson.dumps({"result": "OK"}), headers={"set-cookie": "sid=1"}
        )

    return httpx.MockTransport(handler)


def _async_recording_inner(records: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        request.read()
        records.append(request)
        return httpx.Response(200, content=orjson.dumps({"result": "OK"}))

    return httpx.MockTransport(handler)


class TestSyncTransport:
    def test_set_cookie_is_stripped(self):
        transport = VulnersTransport(_recording_inner([]), origin=ORIGIN)
        req = httpx.Request("GET", "https://vulners.com/api", headers={"X-Api-Key": "K"})
        resp = transport.handle_request(req)
        assert "set-cookie" not in resp.headers

    def test_same_origin_keeps_key(self):
        records: list[httpx.Request] = []
        transport = VulnersTransport(_recording_inner(records), origin=ORIGIN)
        req = httpx.Request("GET", "https://vulners.com/api", headers={"X-Api-Key": "K"})
        transport.handle_request(req)
        assert records[0].headers.get("x-api-key") == "K"

    def test_cross_origin_strips_key_header(self):
        records: list[httpx.Request] = []
        transport = VulnersTransport(_recording_inner(records), origin=ORIGIN)
        req = httpx.Request("GET", "https://evil.example/api", headers={"X-Api-Key": "K"})
        transport.handle_request(req)
        assert "x-api-key" not in records[0].headers

    def test_cross_origin_scrubs_key_from_json_body(self):
        records: list[httpx.Request] = []
        transport = VulnersTransport(_recording_inner(records), origin=ORIGIN)
        req = httpx.Request(
            "POST",
            "https://evil.example/api",
            headers={"X-Api-Key": "K"},
            content=orjson.dumps({"apiKey": "K", "q": "x"}),
        )
        req.headers["content-type"] = "application/json"
        transport.handle_request(req)
        assert orjson.loads(records[0].content) == {"q": "x"}

    def test_ssrf_guard_rejects_private_redirect_target(self):
        transport = VulnersTransport(_recording_inner([]), origin=ORIGIN)
        req = httpx.Request("GET", "https://169.254.169.254/latest/meta-data/")
        with pytest.raises(APIConnectionError):
            transport.handle_request(req)

    def test_ssrf_guard_rejects_loopback(self):
        transport = VulnersTransport(_recording_inner([]), origin=ORIGIN)
        req = httpx.Request("GET", "https://127.0.0.1/")
        with pytest.raises(APIConnectionError):
            transport.handle_request(req)


class TestSsrfNumericHosts:
    """Numeric-encoded IP literals (decimal/hex/octal integer hosts) that the OS
    resolver accepts must not slip past the private-address guard."""

    @pytest.mark.parametrize(
        "host",
        [
            "2130706433",  # decimal 127.0.0.1
            "0x7f000001",  # hex 127.0.0.1
            "0X7F000001",  # hex, upper-case prefix
            "017700000001",  # octal 127.0.0.1
        ],
    )
    def test_numeric_loopback_forms_resolve(self, host):
        ip = _host_as_ip(host)
        assert ip is not None
        assert str(ip) == "127.0.0.1"

    def test_numeric_loopback_redirect_is_refused(self):
        with pytest.raises(APIConnectionError):
            _guard_redirect_target(httpx.URL("http://placeholder/").copy_with(host="2130706433"))

    def test_dotted_literal_still_parsed(self):
        ip = _host_as_ip("10.0.0.5")
        assert ip is not None and ip.is_private

    def test_dns_name_is_not_an_ip_literal(self):
        # A real hostname is delegated unchanged (base stays None) — literal-only.
        assert _host_as_ip("storage.googleapis.com") is None

    def test_bare_zero_is_unspecified(self):
        ip = _host_as_ip("0")
        assert ip is not None and ip.is_unspecified

    @pytest.mark.parametrize(
        "host,expected",
        [
            ("127.1", "127.0.0.1"),  # dotted short-form (a.d)
            ("0x7f.0.0.1", "127.0.0.1"),  # per-octet hex
            ("0177.0.0.1", "127.0.0.1"),  # per-octet octal
            ("169.254.43518", "169.254.169.254"),  # 3-part form -> cloud metadata
        ],
    )
    def test_shorthand_and_mixed_radix_forms_parse(self, host, expected):
        # inet_aton accepts these exactly as the OS resolver would; the old int-only
        # parser missed them, so the guard now classifies them.
        ip = _host_as_ip(host)
        assert ip is not None and str(ip) == expected

    @pytest.mark.parametrize("host", ["127.1", "0x7f.0.0.1", "169.254.43518"])
    def test_shorthand_redirect_is_refused(self, host):
        # These pass httpx URL validation, so a hostile redirect could carry them
        # and must be refused (169.254.43518 -> the 169.254.169.254 metadata IP).
        with pytest.raises(APIConnectionError):
            _guard_redirect_target(httpx.URL("http://placeholder/").copy_with(host=host))

    @pytest.mark.parametrize("host", ["0x", "1.2.3.4.5", "256.1.1.1", "storage.example"])
    def test_unparseable_host_is_not_ip(self, host):
        # Not an IP literal in any radix the resolver honours -> delegated as a name.
        assert _host_as_ip(host) is None


class TestAsyncTransport:
    async def test_set_cookie_is_stripped(self):
        inner = httpx.MockTransport(
            lambda r: httpx.Response(200, headers={"set-cookie": "sid=1"})
        )
        transport = AsyncVulnersTransport(inner, origin=ORIGIN)
        req = httpx.Request("GET", "https://vulners.com/api", headers={"X-Api-Key": "K"})
        resp = await transport.handle_async_request(req)
        assert "set-cookie" not in resp.headers

    async def test_cross_origin_strips_key_header(self):
        records: list[httpx.Request] = []
        transport = AsyncVulnersTransport(_async_recording_inner(records), origin=ORIGIN)
        req = httpx.Request("GET", "https://evil.example/api", headers={"X-Api-Key": "K"})
        await transport.handle_async_request(req)
        assert "x-api-key" not in records[0].headers

    async def test_ssrf_guard_rejects_private_redirect_target(self):
        transport = AsyncVulnersTransport(_async_recording_inner([]), origin=ORIGIN)
        req = httpx.Request("GET", "https://10.0.0.5/internal")
        with pytest.raises(APIConnectionError):
            await transport.handle_async_request(req)
