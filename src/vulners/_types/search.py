"""Input TypedDicts for the search resource slice.

Keyword inputs are also expressible as a single mapping via these TypedDicts
(``total=False`` so every key is optional), used by the escape-hatch request
paths and for typing bulk parameter dicts.
"""

from __future__ import annotations

from collections.abc import Sequence

from typing_extensions import TypedDict


class SearchQueryParams(TypedDict, total=False):
    """Parameters accepted by ``search.query`` / the Lucene search endpoint."""

    query: str
    limit: int
    offset: int
    fields: Sequence[str]


class DocumentLookupParams(TypedDict, total=False):
    """Parameters accepted by the multi-document lookup endpoint."""

    id: Sequence[str]
    fields: Sequence[str]
    references: bool


__all__ = ["DocumentLookupParams", "SearchQueryParams"]
