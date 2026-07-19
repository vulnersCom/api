"""Async ``misc`` resource (unasyncd source for the sync ``misc`` resource).

Assorted lookup helpers: CPE search, query autocomplete, field suggestions and
the web-application (burp) rule set.
"""

from __future__ import annotations

from typing import Any, Literal

import httpx

from ..._base_client import RequestSpec
from ..._types import NotGiven, not_given
from . import _base

_SEARCH_CPE = RequestSpec("GET", "/api/v4/search/cpe", body_mode="query", unwrap=("result",))
_AUTOCOMPLETE = RequestSpec(
    "POST", "/api/v3/search/autocomplete/", body_mode="json", unwrap=("data",)
)
_SUGGEST = RequestSpec(
    "POST", "/api/v3/search/suggest/", body_mode="json", unwrap=("data", "suggest")
)
_BURP_RULES = RequestSpec("GET", "/api/v3/burp/rules/", body_mode="query", unwrap=("data",))


def _autocomplete(value: Any) -> list[str]:
    suggestions = value.get("suggestions", []) if isinstance(value, dict) else []
    out: list[str] = []
    for item in suggestions:
        # Each suggestion arrives as ``[completion, ...]``; take the completion.
        out.append(str(item[0]) if isinstance(item, (list, tuple)) and item else str(item))
    return out


class AsyncMisc(_base.AsyncBaseResource):
    """Miscellaneous search and metadata helpers."""

    async def search_cpe(
        self,
        product: str,
        *,
        vendor: str | NotGiven = not_given,
        size: int | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Search for CPE strings matching a product (and optional vendor).

        Args:
            product: Product string to search a CPE for.
            vendor: Optional vendor to narrow the match.
            size: Maximum number of results (0..10000, ``0`` means all).
        """
        body: dict[str, Any] = {"product": product}
        self._set(body, "vendor", vendor)
        self._set(body, "size", size)
        return await self._request(_SEARCH_CPE, body=body, timeout=timeout)

    async def query_autocomplete(
        self,
        query: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> list[str]:
        """Return possible completions for a partial Lucene query."""
        return await self._request(
            _AUTOCOMPLETE, cast=_autocomplete, body={"query": query}, timeout=timeout
        )

    async def get_suggestion(
        self,
        field_name: str,
        *,
        type: Literal["distinct"] = "distinct",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Return distinct value suggestions for a document field.

        Args:
            field_name: The document field to suggest values for.
            type: Suggestion type; only ``"distinct"`` is supported.
        """
        body = {"fieldName": field_name, "type": type}
        return await self._request(_SUGGEST, body=body, timeout=timeout)

    async def get_web_application_rules(
        self,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Return the Vulners web-application (burp) detection rule set."""
        return await self._request(_BURP_RULES, timeout=timeout)


__all__ = ["AsyncMisc"]
