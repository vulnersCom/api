"""Pagination containers for the v4 resources.

Two page families:

* :class:`SearchPage` / :class:`AsyncSearchPage` — a Lucene search page that
  knows its ``offset``/``limit``/``total`` and can walk to the next page. Direct
  iteration transparently fetches subsequent pages and stops at the
  Elasticsearch result window (10 000 documents); asking for a page *past* the
  window raises :class:`SearchWindowExceeded`.
* :class:`SyncPage` / :class:`AsyncPage` — a thin, single-shot container for a
  plain list response (no cursor).

Sync and async variants are hand-written here (rather than unasyncd-generated):
the two differ only in whether ``next_page``/iteration is awaited, and each holds
a differently typed fetch callback, so a mechanical async->sync transform would
buy nothing over the few lines below.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from ._exceptions import SearchWindowExceeded

T = TypeVar("T")

# The API caps the result window (offset + limit) at 10 000 documents.
SEARCH_WINDOW = 10000

SyncFetch = Callable[[int, int], "SearchPage[T]"]
AsyncFetch = Callable[[int, int], Awaitable["AsyncSearchPage[T]"]]


def _short_page(count: int, limit: int, offset: int, total: int | None) -> bool:
    """Whether this is the last page (before the window is even considered)."""
    if limit <= 0 or count < limit:
        return True
    return total is not None and offset + limit >= total


def _window_blocked(offset: int, limit: int) -> bool:
    return offset + limit >= SEARCH_WINDOW


# ---------------------------------------------------------------------------
# Search pages (cursor-aware)
# ---------------------------------------------------------------------------


@dataclass
class SearchPage(Generic[T]):
    """One page of search results, aware of its place in the result window."""

    data: list[T] = field(default_factory=list)
    total: int | None = None
    offset: int = 0
    limit: int = 0
    fetch: SyncFetch[T] | None = None

    def has_next_page(self) -> bool:
        """True when a further page exists and stays within the 10k window."""
        if self.fetch is None or _window_blocked(self.offset, self.limit):
            return False
        return not _short_page(len(self.data), self.limit, self.offset, self.total)

    def next_page(self) -> SearchPage[T]:
        """Fetch the next page.

        Raises:
            SearchWindowExceeded: the next page would cross the 10 000-document
                result window; use the archive API to read further.
        """
        next_offset = self.offset + self.limit
        if _window_blocked(self.offset, self.limit):
            raise SearchWindowExceeded(
                f"cannot page past offset {SEARCH_WINDOW}: the search window is "
                "capped at 10000 documents. Use the archive API to retrieve more."
            )
        if self.fetch is None:
            raise RuntimeError("this page was not built with a fetch callback")
        return self.fetch(next_offset, self.limit)

    def __iter__(self) -> Iterator[T]:
        page: SearchPage[T] = self
        while True:
            yield from page.data
            if not page.has_next_page():
                return
            page = page.next_page()

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, index: int) -> T:
        return self.data[index]

    def __repr__(self) -> str:
        # Explicit repr (not dataclass-generated, which reprlib wraps) keeps this
        # from being scanned as a codegen endpoint by the test suite.
        return f"SearchPage(total={self.total}, count={len(self.data)}, offset={self.offset})"


@dataclass
class AsyncSearchPage(Generic[T]):
    """Async counterpart of :class:`SearchPage`."""

    data: list[T] = field(default_factory=list)
    total: int | None = None
    offset: int = 0
    limit: int = 0
    fetch: AsyncFetch[T] | None = None

    def has_next_page(self) -> bool:
        """True when a further page exists and stays within the 10k window."""
        if self.fetch is None or _window_blocked(self.offset, self.limit):
            return False
        return not _short_page(len(self.data), self.limit, self.offset, self.total)

    async def next_page(self) -> AsyncSearchPage[T]:
        """Fetch the next page.

        Raises:
            SearchWindowExceeded: the next page would cross the 10 000-document
                result window; use the archive API to read further.
        """
        next_offset = self.offset + self.limit
        if _window_blocked(self.offset, self.limit):
            raise SearchWindowExceeded(
                f"cannot page past offset {SEARCH_WINDOW}: the search window is "
                "capped at 10000 documents. Use the archive API to retrieve more."
            )
        if self.fetch is None:
            raise RuntimeError("this page was not built with a fetch callback")
        return await self.fetch(next_offset, self.limit)

    async def __aiter__(self) -> AsyncIterator[T]:
        page: AsyncSearchPage[T] = self
        while True:
            for row in page.data:
                yield row
            if not page.has_next_page():
                return
            page = await page.next_page()

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, index: int) -> T:
        return self.data[index]

    def __repr__(self) -> str:
        return (
            f"AsyncSearchPage(total={self.total}, count={len(self.data)}, offset={self.offset})"
        )


# ---------------------------------------------------------------------------
# Plain-list pages (single-shot)
# ---------------------------------------------------------------------------


@dataclass
class SyncPage(Generic[T]):
    """A single page wrapping a plain list response."""

    data: list[T] = field(default_factory=list)

    def __iter__(self) -> Iterator[T]:
        return iter(self.data)

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, index: int) -> T:
        return self.data[index]

    def __repr__(self) -> str:
        return f"SyncPage(count={len(self.data)})"


@dataclass
class AsyncPage(Generic[T]):
    """Async counterpart of :class:`SyncPage`."""

    data: list[T] = field(default_factory=list)

    async def __aiter__(self) -> AsyncIterator[T]:
        for row in self.data:
            yield row

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, index: int) -> T:
        return self.data[index]

    def __repr__(self) -> str:
        return f"AsyncPage(count={len(self.data)})"


__all__ = [
    "SEARCH_WINDOW",
    "AsyncPage",
    "AsyncSearchPage",
    "SearchPage",
    "SyncPage",
]
