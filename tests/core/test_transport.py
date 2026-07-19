"""Credential-safety policy enforced by the transport wrappers."""

from __future__ import annotations

import httpx
import orjson
import pytest

from vulners._exceptions import APIConnectionError
from vulners._transport import AsyncVulnersTransport, VulnersTransport

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
