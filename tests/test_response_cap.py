"""Opt-in max_response_bytes cap.

Default (None) is byte-identical to the historic behavior; when set, the raw
body and the decompressed output are bounded and a VulnersApiError is raised on
overflow. All payloads are synthetic.
"""

from __future__ import annotations

import gzip
import io
import zipfile
import zlib

import httpx
import pytest

import vulners
from vulners.base import VulnersApiError, VulnersApiTransport

KEY = "SYNTHETIC-TEST-KEY-0000000000"


def _api(server, cap):
    api = vulners.VulnersApi(KEY, max_response_bytes=cap)
    api._client._transport = VulnersApiTransport(httpx.MockTransport(server.handler))
    return api


def _gzip(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as g:
        g.write(data)
    return buf.getvalue()


def _zip_single(data: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("member", data)
    return buf.getvalue()


class TestDefaultUnlimited:
    def test_large_body_byte_identical(self, server):
        payload = b"Z" * 5_000_000
        server.enqueue_raw(payload, "application/octet-stream")
        api = _api(server, None)
        try:
            out = api._invoke("GET", "/x", {}, (), parse_content=False)
        finally:
            api.close()
        assert out == payload

    def test_gzip_archive_matches_zlib(self, server):
        raw = b"A" * 2_000_000
        gz = _gzip(raw)
        server.enqueue_raw(gz, "application/x-gzip-compressed")
        api = _api(server, None)
        try:
            out = api._invoke("GET", "/x", {}, (), parse_content=False)
        finally:
            api.close()
        assert out == raw == zlib.decompress(gz, wbits=31)


class TestCapEnforced:
    def test_raw_body_over_cap_raises(self, server):
        server.enqueue_raw(b"B" * 1000, "application/octet-stream")
        api = _api(server, 100)
        try:
            with pytest.raises(VulnersApiError):
                api._invoke("GET", "/x", {}, (), parse_content=False)
        finally:
            api.close()

    def test_declared_content_length_over_cap_raises(self, server):
        server.enqueue_raw(
            b"C" * 10, "application/octet-stream", headers={"content-length": "999999"}
        )
        api = _api(server, 100)
        try:
            with pytest.raises(VulnersApiError):
                api._invoke("GET", "/x", {}, (), parse_content=False)
        finally:
            api.close()

    def test_gzip_bomb_over_cap_raises(self, server):
        gz = _gzip(b"A" * 2_000_000)
        server.enqueue_raw(gz, "application/x-gzip-compressed")
        api = _api(server, 500_000)
        try:
            with pytest.raises(VulnersApiError):
                api._invoke("GET", "/x", {}, (), parse_content=False)
        finally:
            api.close()

    def test_zip_bomb_over_cap_raises(self, server):
        zp = _zip_single(b"A" * 2_000_000)
        server.enqueue_raw(zp, "application/x-zip-compressed")
        api = _api(server, 500_000)
        try:
            with pytest.raises(VulnersApiError):
                api._invoke("GET", "/x", {}, (), parse_content=False)
        finally:
            api.close()


class TestCapWithinBudget:
    def test_gzip_under_cap_byte_identical(self, server):
        raw = b"A" * 1_000_000
        gz = _gzip(raw)
        server.enqueue_raw(gz, "application/x-gzip-compressed")
        api = _api(server, 4_000_000)
        try:
            out = api._invoke("GET", "/x", {}, (), parse_content=False)
        finally:
            api.close()
        assert out == raw == zlib.decompress(gz, wbits=31)

    def test_zip_under_cap_byte_identical(self, server):
        raw = b"A" * 1_000_000
        server.enqueue_raw(_zip_single(raw), "application/x-zip-compressed")
        api = _api(server, 4_000_000)
        try:
            out = api._invoke("GET", "/x", {}, (), parse_content=False)
        finally:
            api.close()
        assert out == raw

    def test_json_under_cap_works(self, server):
        server.enqueue_envelope({"v": 1})
        api = _api(server, 1_000_000)
        try:
            assert api._invoke("GET", "/x", {}, ()) == {"v": 1}
        finally:
            api.close()
