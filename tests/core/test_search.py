"""Search resource happy paths for both the sync and async clients (respx)."""

from __future__ import annotations

import httpx
import orjson
import pytest
import respx

from vulners._client import AsyncVulners, Vulners
from vulners._exceptions import SearchWindowExceeded
from vulners._models.bulletin import Bulletin

KEY = "SYNTHETIC-TEST-KEY"


def _envelope(data: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": "OK", "data": data}))


def _search_data(*ids: str) -> dict:
    return {
        "search": [{"_source": {"id": i, "cvss": {"score": 9.1}}} for i in ids],
        "total": len(ids),
    }


class TestSyncSearch:
    @respx.mock
    def test_query_request_shape_and_parsing(self):
        route = respx.post("https://vulners.com/api/v3/search/lucene/").mock(
            return_value=_envelope(_search_data("CVE-2099-1", "CVE-2099-2"))
        )
        with Vulners(KEY) as client:
            page = client.search.query("ssh", limit=10, offset=0)

        assert page.total == 2
        assert [b.id for b in page] == ["CVE-2099-1", "CVE-2099-2"]
        assert all(isinstance(b, Bulletin) for b in page)
        req = route.calls.last.request
        assert req.method == "POST"
        assert orjson.loads(req.content) == {"query": "ssh", "size": 10, "skip": 0}
        assert req.headers["x-api-key"] == KEY

    @respx.mock
    def test_query_sends_fields_when_given(self):
        route = respx.post("https://vulners.com/api/v3/search/lucene/").mock(
            return_value=_envelope(_search_data())
        )
        with Vulners(KEY) as client:
            client.search.query("ssh", fields=["id", "title"])
        assert orjson.loads(route.calls.last.request.content)["fields"] == ["id", "title"]

    def test_query_offset_beyond_window_raises(self):
        with Vulners(KEY) as client:
            with pytest.raises(SearchWindowExceeded):
                client.search.query("ssh", offset=10000)

    @respx.mock
    def test_get_bulletin_found(self):
        respx.post("https://vulners.com/api/v3/search/id/").mock(
            return_value=_envelope({"documents": {"CVE-2099-1": {"id": "CVE-2099-1"}}})
        )
        with Vulners(KEY) as client:
            bulletin = client.search.get_bulletin("CVE-2099-1")
        assert isinstance(bulletin, Bulletin)
        assert bulletin.id == "CVE-2099-1"

    @respx.mock
    def test_get_bulletin_missing_is_none(self):
        respx.post("https://vulners.com/api/v3/search/id/").mock(
            return_value=_envelope({"documents": {}})
        )
        with Vulners(KEY) as client:
            assert client.search.get_bulletin("CVE-0000-0") is None

    @respx.mock
    def test_get_multiple_bulletins(self):
        respx.post("https://vulners.com/api/v3/search/id/").mock(
            return_value=_envelope({"documents": {"A": {"id": "A"}, "B": {"id": "B"}}})
        )
        with Vulners(KEY) as client:
            docs = client.search.get_multiple_bulletins(["A", "B"])
        assert set(docs) == {"A", "B"}
        assert docs["A"].id == "A"

    @respx.mock
    def test_with_raw_response_exposes_status_and_parse(self):
        respx.post("https://vulners.com/api/v3/search/lucene/").mock(
            return_value=_envelope(_search_data("CVE-2099-9"))
        )
        with Vulners(KEY) as client:
            raw = client.search.with_raw_response.query("ssh")
        assert raw.status_code == 200
        page = raw.parse()
        assert page.total == 1
        assert page.data[0].id == "CVE-2099-9"


class TestAsyncSearch:
    @respx.mock
    async def test_query_request_shape_and_parsing(self):
        route = respx.post("https://vulners.com/api/v3/search/lucene/").mock(
            return_value=_envelope(_search_data("CVE-2099-1"))
        )
        async with AsyncVulners(KEY) as client:
            page = await client.search.query("ssh", limit=5)

        assert page.total == 1
        assert page.data[0].id == "CVE-2099-1"
        assert orjson.loads(route.calls.last.request.content) == {
            "query": "ssh",
            "size": 5,
            "skip": 0,
        }

    async def test_query_offset_beyond_window_raises(self):
        async with AsyncVulners(KEY) as client:
            with pytest.raises(SearchWindowExceeded):
                await client.search.query("ssh", offset=20000)

    @respx.mock
    async def test_get_bulletin_found(self):
        respx.post("https://vulners.com/api/v3/search/id/").mock(
            return_value=_envelope({"documents": {"CVE-2099-1": {"id": "CVE-2099-1"}}})
        )
        async with AsyncVulners(KEY) as client:
            bulletin = await client.search.get_bulletin("CVE-2099-1")
        assert bulletin is not None
        assert bulletin.id == "CVE-2099-1"
