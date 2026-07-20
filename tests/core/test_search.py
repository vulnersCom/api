"""Search resource happy paths for both the sync and async clients (respx)."""

from __future__ import annotations

import httpx
import orjson
import pytest
import respx

from vulners._client import AsyncVulners, Vulners
from vulners._exceptions import SearchWindowExceeded
from vulners._models.bulletin import Bulletin
from vulners._resources._async.search import DEFAULT_SEARCH_FIELDS

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
        assert orjson.loads(req.content) == {
            "query": "ssh",
            "size": 10,
            "skip": 0,
            "fields": list(DEFAULT_SEARCH_FIELDS),
        }
        assert req.headers["x-api-key"] == KEY

    @respx.mock
    def test_query_sends_fields_when_given(self):
        route = respx.post("https://vulners.com/api/v3/search/lucene/").mock(
            return_value=_envelope(_search_data())
        )
        with Vulners(KEY) as client:
            client.search.query("ssh", fields=["id", "title"])
        assert orjson.loads(route.calls.last.request.content)["fields"] == ["id", "title"]

    @respx.mock
    def test_query_default_fields_are_compact(self):
        # When fields is omitted, the compact default projection is sent; the
        # heavy document fields stay opt-in (fields=["*"] or an explicit list).
        route = respx.post("https://vulners.com/api/v3/search/lucene/").mock(
            return_value=_envelope(_search_data())
        )
        with Vulners(KEY) as client:
            client.search.query("ssh")
        sent = orjson.loads(route.calls.last.request.content)["fields"]
        assert sent == list(DEFAULT_SEARCH_FIELDS)
        assert "sourceData" not in sent
        assert "description" not in sent

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
            "fields": list(DEFAULT_SEARCH_FIELDS),
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


def _v4(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": payload}))


class TestSearchExploits:
    LUCENE = "https://vulners.com/api/v3/search/lucene/"

    @respx.mock
    def test_bare_cve_is_phrase_quoted(self):
        route = respx.post(self.LUCENE).mock(return_value=_envelope(_search_data()))
        with Vulners(KEY) as client:
            client.search.exploits("CVE-2021-44228")
        sent = orjson.loads(route.calls.last.request.content)["query"]
        assert sent == 'bulletinFamily:exploit AND ("CVE-2021-44228")'

    @respx.mock
    def test_plain_query_is_not_quoted(self):
        route = respx.post(self.LUCENE).mock(return_value=_envelope(_search_data()))
        with Vulners(KEY) as client:
            client.search.exploits("wordpress", limit=5, offset=1)
        body = orjson.loads(route.calls.last.request.content)
        assert body["query"] == "bulletinFamily:exploit AND (wordpress)"
        assert body["size"] == 5
        assert body["skip"] == 1

    @respx.mock
    def test_lucene_true_skips_cve_quoting(self):
        route = respx.post(self.LUCENE).mock(return_value=_envelope(_search_data()))
        with Vulners(KEY) as client:
            client.search.exploits("CVE-2021-44228", lucene=True)
        sent = orjson.loads(route.calls.last.request.content)["query"]
        assert sent == "bulletinFamily:exploit AND (CVE-2021-44228)"

    def test_exploit_search_query_helper(self):
        from vulners._resources._sync.search import exploit_search_query

        assert (
            exploit_search_query("  cve-2024-1  ") == 'bulletinFamily:exploit AND ("cve-2024-1")'
        )
        assert exploit_search_query("nginx") == "bulletinFamily:exploit AND (nginx)"
        assert (
            exploit_search_query("CVE-2024-1", lucene=True)
            == "bulletinFamily:exploit AND (CVE-2024-1)"
        )


class TestSearchCollectionsAndDelegates:
    @respx.mock
    def test_collections_unwraps_result(self):
        respx.get("https://vulners.com/api/v4/search/collections").mock(
            return_value=_v4([{"type": "cve", "count": 1}])
        )
        with Vulners(KEY) as client:
            assert client.search.collections() == [{"type": "cve", "count": 1}]

    @respx.mock
    def test_autocomplete_delegate(self):
        route = respx.post("https://vulners.com/api/v3/search/autocomplete/").mock(
            return_value=_envelope({"suggestions": ["type:cve"]})
        )
        with Vulners(KEY) as client:
            assert client.search.autocomplete("type") == ["type:cve"]
        assert orjson.loads(route.calls.last.request.content) == {"query": "type"}

    @respx.mock
    def test_suggest_delegate(self):
        route = respx.post("https://vulners.com/api/v3/search/suggest/").mock(
            return_value=_envelope({"suggest": ["cve", "nessus"]})
        )
        with Vulners(KEY) as client:
            assert client.search.suggest("type") == ["cve", "nessus"]
        assert orjson.loads(route.calls.last.request.content) == {
            "fieldName": "type",
            "type": "distinct",
        }

    @respx.mock
    def test_cpe_delegate(self):
        route = respx.get("https://vulners.com/api/v4/search/cpe").mock(
            return_value=_v4([{"cpe": "x"}])
        )
        with Vulners(KEY) as client:
            assert client.search.cpe("nginx", vendor="f5", size=3) == [{"cpe": "x"}]
        params = route.calls.last.request.url.params
        assert params["product"] == "nginx"
        assert params["vendor"] == "f5"
        assert params["size"] == "3"

    @respx.mock
    def test_web_vulns_delegate(self):
        respx.get("https://vulners.com/api/v3/burp/rules/").mock(
            return_value=_envelope({"rules": []})
        )
        with Vulners(KEY) as client:
            assert client.search.web_vulns() == {"rules": []}
