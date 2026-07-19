"""Async ``search`` resource (unasyncd source for the sync ``search`` resource).

Representative slice of the search domain: Lucene search returning a typed
:class:`SearchPage`, and single / multi document lookup.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import httpx

from ..._base_client import RequestSpec
from ..._exceptions import SearchWindowExceeded
from ..._models._base import construct_type
from ..._models.bulletin import Bulletin
from ..._models.page import SearchPage
from ..._types import NotGiven, not_given
from . import _base

# The API caps the result window (offset + limit) at 10000 documents.
_SEARCH_WINDOW = 10000

_SEARCH_SPEC = RequestSpec(
    "POST", "/api/v3/search/lucene/", body_mode="json", unwrap=("data",), idempotent=True
)
_LOOKUP_SPEC = RequestSpec(
    "POST", "/api/v3/search/id/", body_mode="json", unwrap=("data",), idempotent=True
)


def _page_from(data: Any) -> SearchPage[Bulletin]:
    hits = data.get("search", []) if isinstance(data, dict) else []
    rows = [
        construct_type(hit.get("_source", {}), Bulletin) for hit in hits if isinstance(hit, dict)
    ]
    total = data.get("total") if isinstance(data, dict) else None
    return SearchPage(data=rows, total=total)


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
    ) -> SearchPage[Bulletin]:
        """Search using Lucene query syntax.

        Args:
            query: A Vulners Lucene query (see https://vulners.com/help).
            limit: Maximum number of documents to return.
            offset: Number of documents to skip.
            fields: Restrict the returned fields; the server default is used when
                omitted.

        Returns:
            A :class:`SearchPage` of :class:`Bulletin`; ``.total`` is the total
            match count.

        Raises:
            SearchWindowExceeded: ``offset`` is at or beyond the 10000-document
                window; use the archive API to page further.
        """
        if offset >= _SEARCH_WINDOW:
            raise SearchWindowExceeded(
                f"offset must be less than {_SEARCH_WINDOW} (got {offset}); the search "
                "window is capped at 10000 documents. Use the archive API to retrieve more."
            )
        size = min(limit, _SEARCH_WINDOW - offset)
        body: dict[str, Any] = {"query": query, "size": size, "skip": offset}
        if not isinstance(fields, NotGiven):
            body["fields"] = list(fields)
        return await self._request(_SEARCH_SPEC, cast=_page_from, body=body, timeout=timeout)

    async def get_multiple_bulletins(
        self,
        ids: Sequence[str],
        *,
        fields: Sequence[str] | NotGiven = not_given,
        references: bool = False,
    ) -> dict[str, Bulletin]:
        """Fetch several documents by id, keyed by id."""
        body: dict[str, Any] = {"id": list(ids), "references": references}
        if not isinstance(fields, NotGiven):
            body["fields"] = list(fields)

        def _cast(data: Any) -> dict[str, Bulletin]:
            docs = data.get("documents", {}) if isinstance(data, dict) else {}
            return {
                key: construct_type(value, Bulletin)
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
        """Fetch a single document by id, or ``None`` if it does not exist."""
        body: dict[str, Any] = {"id": [id], "references": False}
        if not isinstance(fields, NotGiven):
            body["fields"] = list(fields)

        def _cast(data: Any) -> Bulletin | None:
            docs = data.get("documents", {}) if isinstance(data, dict) else {}
            raw = docs.get(id)
            return construct_type(raw, Bulletin) if isinstance(raw, dict) else None

        return await self._request(_LOOKUP_SPEC, cast=_cast, body=body)


__all__ = ["AsyncSearch"]
