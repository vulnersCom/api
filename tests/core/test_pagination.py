"""SearchPage cursors, auto-iteration, the 10k window, and iter_query."""

from __future__ import annotations

import httpx
import orjson
import pytest
import respx

from vulners._client import AsyncVulners, Vulners
from vulners._exceptions import SearchWindowExceeded
from vulners._pagination import (
    AsyncPage,
    AsyncSearchPage,
    SearchPage,
    SyncPage,
)

KEY = "SYNTHETIC-TEST-KEY"
LUCENE = "https://vulners.com/api/v3/search/lucene/"


def _sync_fetch(offset: int, size: int) -> SearchPage[int]:
    return SearchPage(
        data=list(range(offset, offset + size)),
        total=1_000_000,
        offset=offset,
        limit=size,
        fetch=_sync_fetch,
    )


async def _async_fetch(offset: int, size: int) -> AsyncSearchPage[int]:
    return AsyncSearchPage(
        data=list(range(offset, offset + size)),
        total=1_000_000,
        offset=offset,
        limit=size,
        fetch=_async_fetch,
    )


class TestSearchPageCursor:
    def test_next_page_fetches_next_offset(self):
        page = _sync_fetch(0, 20)
        nxt = page.next_page()
        assert nxt.offset == 20
        assert nxt.data[0] == 20

    def test_short_page_has_no_next(self):
        page = SearchPage(data=[1, 2], total=2, offset=0, limit=20, fetch=_sync_fetch)
        assert page.has_next_page() is False

    def test_total_reached_has_no_next(self):
        page = SearchPage(data=list(range(20)), total=20, offset=0, limit=20, fetch=_sync_fetch)
        assert page.has_next_page() is False

    def test_page_without_fetch_has_no_next(self):
        page = SearchPage(data=list(range(20)), total=1000, offset=0, limit=20)
        assert page.has_next_page() is False

    def test_page_just_inside_window_has_next(self):
        page = SearchPage(
            data=list(range(20)), total=1_000_000, offset=9960, limit=20, fetch=_sync_fetch
        )
        assert page.has_next_page() is True
        assert page.next_page().offset == 9980

    def test_next_page_at_window_raises(self):
        page = SearchPage(
            data=list(range(20)), total=1_000_000, offset=9980, limit=20, fetch=_sync_fetch
        )
        assert page.has_next_page() is False
        with pytest.raises(SearchWindowExceeded):
            page.next_page()

    def test_auto_iteration_across_finite_pages(self):
        def fetch(offset: int, size: int) -> SearchPage[int]:
            data = list(range(offset, min(offset + size, 6)))
            return SearchPage(data=data, total=6, offset=offset, limit=size, fetch=fetch)

        page = fetch(0, 2)
        assert list(page) == [0, 1, 2, 3, 4, 5]

    def test_auto_iteration_stops_at_window(self):
        calls: list[int] = []

        def fetch(offset: int, size: int) -> SearchPage[int]:
            calls.append(offset)
            return SearchPage(
                data=list(range(offset, offset + size)),
                total=1_000_000,
                offset=offset,
                limit=size,
                fetch=fetch,
            )

        page = SearchPage(
            data=list(range(2000)), total=1_000_000, offset=0, limit=2000, fetch=fetch
        )
        items = list(page)
        assert calls == [2000, 4000, 6000, 8000]  # never fetches past the window
        assert len(items) == 10000
        assert items[-1] == 9999


class TestAsyncSearchPageCursor:
    async def test_next_page_fetches_next_offset(self):
        page = await _async_fetch(0, 20)
        nxt = await page.next_page()
        assert nxt.offset == 20

    async def test_next_page_at_window_raises(self):
        page = AsyncSearchPage(
            data=list(range(20)), total=1_000_000, offset=9980, limit=20, fetch=_async_fetch
        )
        assert page.has_next_page() is False
        with pytest.raises(SearchWindowExceeded):
            await page.next_page()

    async def test_auto_iteration_across_finite_pages(self):
        async def fetch(offset: int, size: int) -> AsyncSearchPage[int]:
            data = list(range(offset, min(offset + size, 6)))
            return AsyncSearchPage(data=data, total=6, offset=offset, limit=size, fetch=fetch)

        page = await fetch(0, 2)
        assert [row async for row in page] == [0, 1, 2, 3, 4, 5]


class TestPlainPages:
    def test_sync_page(self):
        page = SyncPage(data=[1, 2, 3])
        assert list(page) == [1, 2, 3]
        assert len(page) == 3
        assert page[0] == 1

    async def test_async_page(self):
        page = AsyncPage(data=[1, 2, 3])
        assert [x async for x in page] == [1, 2, 3]
        assert len(page) == 3


def _search_handler(request: httpx.Request) -> httpx.Response:
    body = orjson.loads(request.content)
    skip, size = body["skip"], body["size"]
    total = 250
    ids = [f"CVE-{i}" for i in range(skip, min(skip + size, total))]
    data = {"search": [{"_source": {"id": i}} for i in ids], "total": total}
    return httpx.Response(200, content=orjson.dumps({"result": "OK", "data": data}))


class TestQueryIntegration:
    @respx.mock
    def test_query_returns_cursor_page(self):
        respx.post(LUCENE).mock(side_effect=_search_handler)
        with Vulners(KEY) as client:
            page = client.search.query("ssh", limit=100, offset=0)
            assert page.total == 250
            assert page.offset == 0
            assert page.limit == 100
            assert page.has_next_page() is True
            assert page.next_page().offset == 100

    @respx.mock
    def test_iter_query_auto_paginates(self):
        respx.post(LUCENE).mock(side_effect=_search_handler)
        with Vulners(KEY) as client:
            ids = [b.id for b in client.search.iter_query("ssh", page_size=100)]
        assert len(ids) == 250  # 100 + 100 + 50 (short last page stops)
        assert ids[0] == "CVE-0"
        assert ids[-1] == "CVE-249"

    def test_query_offset_beyond_window_raises(self):
        with Vulners(KEY) as client:
            with pytest.raises(SearchWindowExceeded):
                client.search.query("ssh", offset=10000)


class TestQueryIntegrationAsync:
    @respx.mock
    async def test_iter_query_auto_paginates(self):
        respx.post(LUCENE).mock(side_effect=_search_handler)
        async with AsyncVulners(KEY) as client:
            ids = [b.id async for b in client.search.iter_query("ssh", page_size=100)]
        assert len(ids) == 250
        assert ids[-1] == "CVE-249"

    @respx.mock
    async def test_query_next_page(self):
        respx.post(LUCENE).mock(side_effect=_search_handler)
        async with AsyncVulners(KEY) as client:
            page = await client.search.query("ssh", limit=100)
            assert page.has_next_page() is True
            nxt = await page.next_page()
        assert nxt.offset == 100
