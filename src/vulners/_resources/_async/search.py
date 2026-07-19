"""Async ``search`` resource (unasyncd source for the sync ``search`` resource).

Representative slice of the search domain: Lucene search returning a typed
:class:`AsyncSearchPage` (cursor-aware, auto-paginating to the 10k window), an
auto-paginating :meth:`aiter_query`, and single / multi document lookup. Rows are
built through :func:`construct_bulletin`, so each row is the family-specific
:class:`Bulletin` subclass for its ``bulletinFamily``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Any

import httpx

from ..._base_client import RequestSpec
from ..._exceptions import SearchWindowExceeded
from ..._models.bulletin import Bulletin, construct_bulletin
from ..._pagination import SEARCH_WINDOW, AsyncSearchPage
from ..._types import NotGiven, not_given
from . import _base

_SEARCH_SPEC = RequestSpec(
    "POST", "/api/v3/search/lucene/", body_mode="json", unwrap=("data",), idempotent=True
)
_LOOKUP_SPEC = RequestSpec(
    "POST", "/api/v3/search/id/", body_mode="json", unwrap=("data",), idempotent=True
)


class AsyncSearch(_base.AsyncBaseResource):
    """Search the Vulners database."""

    async def query(
        self,
        query: str,
        *,
        limit: int = 20,
        offset: int = 0,
        fields: Sequence[str] | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> AsyncSearchPage[Bulletin]:
        """Search using Lucene query syntax.

        Args:
            query: A Vulners Lucene query (see https://vulners.com/help).
            limit: Maximum number of documents to return in this page.
            offset: Number of documents to skip.
            fields: Restrict the returned fields; the server default is used when
                omitted.

        Returns:
            A cursor-aware :class:`AsyncSearchPage` of :class:`Bulletin`;
            ``.total`` is the total match count and iterating the page walks
            further pages up to the 10000-document window.

        Raises:
            SearchWindowExceeded: ``offset`` is at or beyond the 10000-document
                window; use the archive API to page further.
        """
        if offset >= SEARCH_WINDOW:
            raise SearchWindowExceeded(
                f"offset must be less than {SEARCH_WINDOW} (got {offset}); the search "
                "window is capped at 10000 documents. Use the archive API to retrieve more."
            )
        size = min(limit, SEARCH_WINDOW - offset)
        body: dict[str, Any] = {"query": query, "size": size, "skip": offset}
        self._set(body, "fields", fields, list)

        async def _fetch(next_offset: int, next_size: int) -> AsyncSearchPage[Bulletin]:
            return await self.query(
                query, limit=next_size, offset=next_offset, fields=fields, timeout=timeout
            )

        def _build(data: Any) -> AsyncSearchPage[Bulletin]:
            hits = data.get("search", []) if isinstance(data, dict) else []
            rows = [
                construct_bulletin(hit.get("_source", {}))
                for hit in hits
                if isinstance(hit, dict)
            ]
            total = data.get("total") if isinstance(data, dict) else None
            return AsyncSearchPage(
                data=rows, total=total, offset=offset, limit=size, fetch=_fetch
            )

        return await self._request(_SEARCH_SPEC, cast=_build, body=body, timeout=timeout)

    async def aiter_query(
        self,
        query: str,
        *,
        page_size: int = 100,
        fields: Sequence[str] | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> AsyncIterator[Bulletin]:
        """Iterate every matching :class:`Bulletin`, auto-paginating.

        Fetches pages of ``page_size`` documents and yields their rows lazily,
        stopping at the 10000-document search window.
        """
        page = await self.query(query, limit=page_size, offset=0, fields=fields, timeout=timeout)
        while True:
            for row in page.data:
                yield row
            if not page.has_next_page():
                return
            page = await page.next_page()

    async def get_multiple_bulletins(
        self,
        ids: Sequence[str],
        *,
        fields: Sequence[str] | NotGiven = not_given,
        references: bool = False,
    ) -> dict[str, Bulletin]:
        """Fetch several documents by id, keyed by id.

        Args:
            ids: Document ids to fetch (e.g. ``CVE-2021-44228``). The returned
                mapping is keyed by these ids; ids with no matching document are
                absent from the result.
            fields: Restrict the returned fields on each document; the server
                default projection is used when omitted.
            references: When ``True``, also resolve and include documents the
                requested bulletins reference/cross-link (e.g. the exploits and
                advisories tied to a CVE); defaults to ``False``.

        Returns:
            A mapping of id to the family-specific :class:`Bulletin`.
        """
        body: dict[str, Any] = {"id": list(ids), "references": references}
        self._set(body, "fields", fields, list)

        def _cast(data: Any) -> dict[str, Bulletin]:
            docs = data.get("documents", {}) if isinstance(data, dict) else {}
            return {
                key: construct_bulletin(value)
                for key, value in docs.items()
                if isinstance(value, dict)
            }

        return await self._request(_LOOKUP_SPEC, cast=_cast, body=body)

    async def get_bulletin(
        self,
        id: str,
        *,
        fields: Sequence[str] | NotGiven = not_given,
    ) -> Bulletin | None:
        """Fetch a single document by id, or ``None`` if it does not exist.

        Args:
            id: The document id to fetch (e.g. ``CVE-2021-44228``).
            fields: Restrict the returned fields; the server default projection
                is used when omitted.

        Returns:
            The family-specific :class:`Bulletin`, or ``None`` if no document
            matches ``id``.
        """
        body: dict[str, Any] = {"id": [id], "references": False}
        self._set(body, "fields", fields, list)

        def _cast(data: Any) -> Bulletin | None:
            docs = data.get("documents", {}) if isinstance(data, dict) else {}
            raw = docs.get(id)
            return construct_bulletin(raw) if isinstance(raw, dict) else None

        return await self._request(_LOOKUP_SPEC, cast=_cast, body=body)


__all__ = ["AsyncSearch"]
