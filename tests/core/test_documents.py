"""Documents resource request-wire and parsing for both clients (respx)."""

from __future__ import annotations

import httpx
import orjson
import pytest
import respx

from vulners import NotFoundError
from vulners._client import AsyncVulners, Vulners
from vulners._models.bulletin import Bulletin
from vulners._pagination import ReferencesPage

KEY = "SYNTHETIC-TEST-KEY"
LOOKUP = "https://vulners.com/api/v3/search/id/"
HISTORY = "https://vulners.com/api/v3/search/history"
REFERENCES = "https://vulners.com/api/v4/search/references"


def _v3(payload: object, status: int = 200) -> httpx.Response:
    return httpx.Response(status, content=orjson.dumps({"result": "OK", "data": payload}))


def _refs_page(
    references: object, *, total: object = 5, by_type: object = None
) -> httpx.Response:
    by_type = {"exploitdb": 2, "nessus": 3} if by_type is None else by_type
    body = {"total": total, "totalByType": by_type, "references": references}
    return httpx.Response(200, content=orjson.dumps({"result": body}))


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

    @respx.mock
    def test_references_accepts_206_partial_content(self):
        # search/id answers 206 when a references list is cut at 1000; same body.
        respx.post(LOOKUP).mock(
            return_value=_v3({"references": {"CVE-1": {"nessus": [{"id": "N-1"}]}}}, status=206)
        )
        with Vulners(KEY) as client:
            refs = client.documents.references("CVE-1")
        assert [b.id for b in refs["nessus"]] == ["N-1"]


class TestListReferencesSync:
    @respx.mock
    def test_wire_and_parsing(self):
        route = respx.get(REFERENCES).mock(
            return_value=_refs_page(
                {
                    "nessus": [{"id": "B-2", "type": "nessus"}, {"id": "D-4", "type": "nessus"}],
                    "exploitdb": [
                        {"id": "A-1", "type": "exploitdb", "title": "t"},
                        {"id": "C-3", "type": "exploitdb", "missing": True},
                        "not-a-doc",
                    ],
                    "weird": "not-a-list",
                }
            )
        )
        with Vulners(KEY) as client:
            page = client.documents.list_references(
                "CVE-2099-1", type="exploitdb", limit=4, offset=8, fields=["title", "published"]
            )
        params = route.calls.last.request.url.params
        assert params["id"] == "CVE-2099-1"
        assert params["type"] == "exploitdb"
        assert params["skip"] == "8"
        assert params["size"] == "4"
        # One JSON-encoded array, not repeated ``fields=`` parameters.
        assert params.get_list("fields") == ['["title", "published"]']
        assert isinstance(page, ReferencesPage)
        assert [b.id for b in page] == ["A-1", "B-2", "D-4"]
        assert page.missing == ["C-3"]
        assert page.total == 5
        assert page.total_by_type == {"exploitdb": 2, "nessus": 3}
        assert (page.offset, page.limit, page.entries) == (8, 4, 4)
        assert len(page) == 3 and page[0].id == "A-1"
        assert repr(page) == "ReferencesPage(total=5, count=3, missing=1, offset=8)"

    @respx.mock
    def test_defaults_omit_optional_params(self):
        route = respx.get(REFERENCES).mock(return_value=_refs_page({}))
        with Vulners(KEY) as client:
            page = client.documents.list_references("CVE-2099-1")
        params = route.calls.last.request.url.params
        assert dict(params) == {"id": "CVE-2099-1", "skip": "0", "size": "20"}
        assert page.data == [] and page.missing == []
        assert not page.has_next_page()

    @respx.mock
    def test_iteration_walks_every_page_counting_missing_entries(self):
        # A stale entry keeps its position: a page with fewer documents than
        # ``limit`` is not the last one when the relation continues.
        pages = [
            _refs_page({"cve": [{"id": "A"}, {"id": "B", "missing": True}]}, total=5),
            _refs_page({"cve": [{"id": "C"}, {"id": "D"}]}, total=5),
            _refs_page({"cve": [{"id": "E"}]}, total=5),
        ]
        route = respx.get(REFERENCES).mock(side_effect=pages)
        with Vulners(KEY) as client:
            ids = [b.id for b in client.documents.list_references("X", limit=2)]
        assert ids == ["A", "C", "D", "E"]
        assert [c.request.url.params["skip"] for c in route.calls] == ["0", "2", "4"]

    @respx.mock
    def test_type_filter_pages_by_the_type_count(self):
        # ``total`` covers the whole relation; paging must stop at the type's count.
        route = respx.get(REFERENCES).mock(
            return_value=_refs_page(
                {"exploitdb": [{"id": "E-1"}, {"id": "E-2"}]},
                total=1000,
                by_type={"exploitdb": 2},
            )
        )
        with Vulners(KEY) as client:
            page = client.documents.list_references("X", type="exploitdb", limit=2)
            assert not page.has_next_page()
            assert [b.id for b in page] == ["E-1", "E-2"]
            unknown = client.documents.list_references("X", type="nope", limit=2)
            assert not unknown.has_next_page()
        assert route.call_count == 2

    @respx.mock
    def test_malformed_body_is_an_empty_last_page(self):
        respx.get(REFERENCES).mock(
            return_value=httpx.Response(200, content=orjson.dumps({"result": "garbage"}))
        )
        with Vulners(KEY) as client:
            page = client.documents.list_references("X")
        assert page.data == [] and page.total is None and page.total_by_type == {}
        assert not page.has_next_page()

    @respx.mock
    def test_unknown_bulletin_raises_not_found(self):
        respx.get(REFERENCES).mock(
            return_value=httpx.Response(
                404,
                content=orjson.dumps(
                    {"result": "error", "data": {"error": "Bulletin not found", "errorCode": 227}}
                ),
            )
        )
        with Vulners(KEY) as client, pytest.raises(NotFoundError):
            client.documents.list_references("NOPE-1")

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"limit": 0}, "limit must be between 1 and 100"),
            ({"limit": 101}, "limit must be between 1 and 100"),
            ({"offset": -1}, "offset must be >= 0"),
        ],
    )
    def test_rejects_out_of_range_paging(self, kwargs, message):
        with Vulners(KEY) as client, pytest.raises(ValueError, match=message):
            client.documents.list_references("X", **kwargs)

    def test_page_without_fetch_callback(self):
        page: ReferencesPage[Bulletin] = ReferencesPage(limit=2, entries=2, matching=10)
        assert not page.has_next_page()
        with pytest.raises(RuntimeError, match="fetch callback"):
            page.next_page()


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

    @respx.mock
    async def test_list_references_iterates_pages(self):
        pages = [
            _refs_page({"cve": [{"id": "A"}, {"id": "B", "missing": True}]}, total=3),
            _refs_page({"cve": [{"id": "C"}]}, total=3),
        ]
        route = respx.get(REFERENCES).mock(side_effect=pages)
        async with AsyncVulners(KEY) as client:
            page = await client.documents.list_references("X", limit=2, fields=["id"])
            assert page.missing == ["B"]
            assert len(page) == 1 and page[0].id == "A"
            assert repr(page) == "AsyncReferencesPage(total=3, count=1, missing=1, offset=0)"
            ids = [b.id async for b in page]
        assert ids == ["A", "C"]
        assert [c.request.url.params["skip"] for c in route.calls] == ["0", "2"]
        assert route.calls.last.request.url.params["fields"] == '["id"]'

    async def test_list_references_page_without_fetch_callback(self):
        from vulners._pagination import AsyncReferencesPage

        page: AsyncReferencesPage[Bulletin] = AsyncReferencesPage(limit=2, entries=2)
        assert not page.has_next_page()
        with pytest.raises(RuntimeError, match="fetch callback"):
            await page.next_page()

    @respx.mock
    async def test_list_references_type_filter_and_validation(self):
        route = respx.get(REFERENCES).mock(
            return_value=_refs_page({"exploitdb": [{"id": "E-1"}]}, by_type={"exploitdb": 1})
        )
        async with AsyncVulners(KEY) as client:
            page = await client.documents.list_references("X", type="exploitdb", limit=1)
            assert [b.id async for b in page] == ["E-1"]
            with pytest.raises(ValueError, match="limit must be between 1 and 100"):
                await client.documents.list_references("X", limit=0)
            with pytest.raises(ValueError, match="offset must be >= 0"):
                await client.documents.list_references("X", offset=-1)
        assert route.call_count == 1
        assert route.calls.last.request.url.params["type"] == "exploitdb"
