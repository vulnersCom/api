"""Async ``documents`` resource (unasyncd source for the sync ``documents`` resource).

Document-centric lookups: fetch bulletins by id (single or batch, sharing the
same endpoint spec as the ``search`` resource), resolve the documents a bulletin
references, and read a bulletin's per-field edition history.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import httpx

from ..._base_client import RequestSpec
from ..._models.bulletin import Bulletin, construct_bulletin
from ..._types import NotGiven, not_given
from . import _base
from .search import _LOOKUP_SPEC

_HISTORY_SPEC = RequestSpec(
    "GET", "/api/v3/search/history", body_mode="query", unwrap=("data", "result")
)


# Deliberately not Async-prefixed: the class name is shared with the generated
# sync mirror (resources are reached through the client attributes, so the
# module path — _async vs _sync — is what distinguishes the two).
class Documents(_base.AsyncBaseResource):
    """Fetch Vulners documents (bulletins) by id."""

    async def get(
        self,
        id: str,
        *,
        references: bool = False,
        fields: Sequence[str] | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Bulletin | None:
        """Fetch a single document by id, or ``None`` if it does not exist.

        Args:
            id: The document id to fetch (e.g. ``CVE-2021-44228``).
            references: Also resolve the documents this bulletin references
                server-side; fetch them with :meth:`references`.
            fields: Restrict the returned fields; the server default projection
                is used when omitted.

        Returns:
            The family-specific :class:`Bulletin`, or ``None`` if no document
            matches ``id``.
        """
        body: dict[str, Any] = {"id": [id], "references": references}
        self._set(body, "fields", fields, list)

        def _cast(data: Any) -> Bulletin | None:
            docs = data.get("documents", {}) if isinstance(data, dict) else {}
            raw = docs.get(id)
            return construct_bulletin(raw) if isinstance(raw, dict) else None

        return await self._request(_LOOKUP_SPEC, cast=_cast, body=body, timeout=timeout)

    async def get_many(
        self,
        ids: Sequence[str],
        *,
        references: bool = False,
        fields: Sequence[str] | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Bulletin]:
        """Fetch several documents by id, keyed by id.

        Args:
            ids: Document ids to fetch. Ids with no matching document are
                absent from the result.
            references: Also resolve the documents these bulletins reference
                server-side; fetch them with :meth:`references`.
            fields: Restrict the returned fields on each document; the server
                default projection is used when omitted.

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

        return await self._request(_LOOKUP_SPEC, cast=_cast, body=body, timeout=timeout)

    async def references(
        self,
        id: str,
        *,
        fields: Sequence[str] | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, list[Bulletin]]:
        """Fetch the documents a bulletin references, grouped by source type.

        Args:
            id: The document whose references to resolve.
            fields: Restrict the returned fields on each referenced document;
                the server default projection is used when omitted.

        Returns:
            A mapping of source type (e.g. ``"nessus"``, ``"zdt"``) to the
            referencing/referenced :class:`Bulletin` documents; empty when the
            document does not exist or has no references.
        """
        body: dict[str, Any] = {"id": [id], "references": True}
        self._set(body, "fields", fields, list)

        def _cast(data: Any) -> dict[str, list[Bulletin]]:
            refs = data.get("references", {}) if isinstance(data, dict) else {}
            groups = refs.get(id, {}) if isinstance(refs, dict) else {}
            if not isinstance(groups, dict):
                return {}
            return {
                source: [construct_bulletin(doc) for doc in docs if isinstance(doc, dict)]
                for source, docs in groups.items()
                if isinstance(docs, list)
            }

        return await self._request(_LOOKUP_SPEC, cast=_cast, body=body, timeout=timeout)

    async def history(
        self,
        id: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> list[dict[str, Any]]:
        """Read the per-field edition history of a bulletin.

        Args:
            id: The bulletin id (e.g. ``CVE-2024-23622``).

        Returns:
            A list of ``{"field", "value", "published"}`` entries — one per
            recorded field edition, newest first.
        """
        return await self._request(_HISTORY_SPEC, body={"id": id}, timeout=timeout)


__all__ = ["Documents"]
