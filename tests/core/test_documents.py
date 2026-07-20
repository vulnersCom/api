"""Documents resource request-wire and parsing for both clients (respx)."""

from __future__ import annotations

import httpx
import orjson
import respx

from vulners._client import AsyncVulners, Vulners
from vulners._models.bulletin import Bulletin

KEY = "SYNTHETIC-TEST-KEY"
LOOKUP = "https://vulners.com/api/v3/search/id/"
HISTORY = "https://vulners.com/api/v3/search/history"


def _v3(payload: object) -> httpx.Response:
    return httpx.Response(200, content=orjson.dumps({"result": "OK", "data": payload}))


class TestDocumentsSync:
    @respx.mock
    def test_get_found_and_wire(self):
        route = respx.post(LOOKUP).mock(
            return_value=_v3({"documents": {"CVE-2099-1": {"id": "CVE-2099-1"}}})
        )
        with Vulners(KEY) as client:
            bulletin = client.documents.get("CVE-2099-1", fields=["id"])
        assert isinstance(bulletin, Bulletin)
        assert bulletin.id == "CVE-2099-1"
        assert orjson.loads(route.calls.last.request.content) == {
            "id": ["CVE-2099-1"],
            "references": False,
            "fields": ["id"],
        }

    @respx.mock
    def test_get_missing_is_none(self):
        respx.post(LOOKUP).mock(return_value=_v3({"documents": {}}))
        with Vulners(KEY) as client:
            assert client.documents.get("CVE-0000-0") is None

    @respx.mock
    def test_get_many_with_references_flag(self):
        route = respx.post(LOOKUP).mock(
            return_value=_v3({"documents": {"A": {"id": "A"}, "B": {"id": "B"}}})
        )
        with Vulners(KEY) as client:
            docs = client.documents.get_many(["A", "B"], references=True)
        assert set(docs) == {"A", "B"}
        assert docs["A"].id == "A"
        body = orjson.loads(route.calls.last.request.content)
        assert body["id"] == ["A", "B"]
        assert body["references"] is True

    @respx.mock
    def test_references_grouped_by_source(self):
        route = respx.post(LOOKUP).mock(
            return_value=_v3(
                {
                    "documents": {"CVE-2099-1": {"id": "CVE-2099-1"}},
                    "references": {
                        "CVE-2099-1": {
                            "zdt": [{"id": "1337DAY-ID-1"}, "not-a-doc"],
                            "weird": "not-a-list",
                        }
                    },
                }
            )
        )
        with Vulners(KEY) as client:
            refs = client.documents.references("CVE-2099-1", fields=["id"])
        assert set(refs) == {"zdt"}
        assert [b.id for b in refs["zdt"]] == ["1337DAY-ID-1"]
        body = orjson.loads(route.calls.last.request.content)
        assert body["references"] is True
        assert body["fields"] == ["id"]

    @respx.mock
    def test_references_missing_document_is_empty(self):
        respx.post(LOOKUP).mock(return_value=_v3({"documents": {}, "references": {}}))
        with Vulners(KEY) as client:
            assert client.documents.references("CVE-0000-0") == {}

    @respx.mock
    def test_references_non_dict_groups_is_empty(self):
        respx.post(LOOKUP).mock(return_value=_v3({"references": {"CVE-2099-1": ["not-a-dict"]}}))
        with Vulners(KEY) as client:
            assert client.documents.references("CVE-2099-1") == {}

    @respx.mock
    def test_history_unwraps_nested_result(self):
        route = respx.get(HISTORY).mock(
            return_value=_v3({"result": [{"field": "cvss", "published": "2026-01-01"}]})
        )
        with Vulners(KEY) as client:
            out = client.documents.history("CVE-2099-1")
        assert out == [{"field": "cvss", "published": "2026-01-01"}]
        assert route.calls.last.request.url.params["id"] == "CVE-2099-1"


class TestDocumentsAsync:
    @respx.mock
    async def test_get_found_missing_and_many(self):
        respx.post(LOOKUP).mock(
            return_value=_v3({"documents": {"A": {"id": "A"}, "B": {"id": "B"}}})
        )
        async with AsyncVulners(KEY) as client:
            bulletin = await client.documents.get("A", references=True, fields=["id"])
            assert bulletin is not None and bulletin.id == "A"
            missing = await client.documents.get("C")
            assert missing is None
            docs = await client.documents.get_many(["A", "B"], fields=["id"])
            assert set(docs) == {"A", "B"}

    @respx.mock
    async def test_references_and_history(self):
        respx.post(LOOKUP).mock(
            return_value=_v3({"references": {"CVE-1": {"nessus": [{"id": "N-1"}], "bad": "x"}}})
        )
        respx.get(HISTORY).mock(return_value=_v3({"result": [{"field": "epss"}]}))
        async with AsyncVulners(KEY) as client:
            refs = await client.documents.references("CVE-1")
            assert [b.id for b in refs["nessus"]] == ["N-1"]
            assert await client.documents.history("CVE-1") == [{"field": "epss"}]

    @respx.mock
    async def test_references_non_dict_groups_is_empty(self):
        respx.post(LOOKUP).mock(return_value=_v3({"references": {"CVE-1": 42}}))
        async with AsyncVulners(KEY) as client:
            assert await client.documents.references("CVE-1") == {}
