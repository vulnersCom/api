"""Async ``documents`` resource (unasyncd source for the sync ``documents`` resource).

Document-centric lookups: fetch bulletins by id (single or batch, sharing the
same endpoint spec as the ``search`` resource), resolve the documents a bulletin
references (inline, or paged through the whole relation), and read a bulletin's
per-field edition history.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import httpx

from ..._base_client import RequestSpec
from ..._models.bulletin import Bulletin, construct_bulletin
from ..._pagination import AsyncReferencesPage
from ..._types import NotGiven, not_given
from . import _base
from .search import _LOOKUP_SPEC

_HISTORY_SPEC = RequestSpec(
    "GET", "/api/v3/search/history", body_mode="query", unwrap=("data", "result")
)
_REFERENCES_SPEC = RequestSpec(
    "GET", "/api/v4/search/references", body_mode="query", unwrap=("result",)
)

# Page size bound enforced by ``/api/v4/search/references``.
_REFERENCES_MAX_LIMIT = 100


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

        The server returns at most 1000 related documents per bulletin (answering
        ``206 Partial Content`` when it cuts the list); use
        :meth:`list_references` to page through the whole relation.
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

    async def list_references(
        self,
        id: str,
        *,
        type: str | NotGiven = not_given,
        limit: int = 20,
        offset: int = 0,
        fields: Sequence[str] | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> AsyncReferencesPage[Bulletin]:
        """Page through every bulletin related to ``id`` through a shared CVE.

        Unlike :meth:`references`, which is capped at 1000 documents, this walks
        the whole relation: iterating the returned page fetches the following
        pages until the relation is exhausted. Documents are ordered by id,
        ascending, and the order is stable between requests.

        Args:
            id: The bulletin whose related documents to list; any type, not
                only a CVE.
            type: Return only related bulletins of this type (e.g.
                ``"exploitdb"``).
            limit: Number of relation entries per page, 1 to 100.
            offset: Number of relation entries to skip.
            fields: Document fields to return; ``id`` and ``type`` are always
                present. Names outside the public field set are ignored, and the
                full public field set is returned when omitted or when none of
                the names is public.

        Returns:
            A :class:`AsyncReferencesPage` of :class:`Bulletin`. ``.total`` and
            ``.total_by_type`` describe the whole relation as visible to your
            licence, regardless of ``type`` and of the page; ids of related
            documents that no longer exist are listed in ``.missing``.

        Raises:
            NotFoundError: no bulletin with this ``id`` exists.
        """
        if limit < 1 or limit > _REFERENCES_MAX_LIMIT:
            raise ValueError(f"limit must be between 1 and {_REFERENCES_MAX_LIMIT}, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")
        params: dict[str, Any] = {"id": id, "skip": offset, "size": limit}
        self._set(params, "type", type)
        # The endpoint reads ``fields`` as one JSON-encoded array; repeated
        # ``fields=`` parameters are rejected.
        self._set(params, "fields", fields, lambda value: json.dumps(list(value)))

        async def _fetch(next_offset: int, next_limit: int) -> AsyncReferencesPage[Bulletin]:
            return await self.list_references(
                id,
                type=type,
                limit=next_limit,
                offset=next_offset,
                fields=fields,
                timeout=timeout,
            )

        def _build(data: Any) -> AsyncReferencesPage[Bulletin]:
            data = data if isinstance(data, dict) else {}
            buckets = data.get("references")
            entries = [
                entry
                for bucket in (buckets.values() if isinstance(buckets, dict) else ())
                if isinstance(bucket, list)
                for entry in bucket
                if isinstance(entry, dict)
            ]
            # The server buckets one id-ordered page by type; restore that order.
            entries.sort(key=lambda entry: str(entry.get("id", "")))
            total = data.get("total")
            total_by_type = data.get("totalByType")
            total_by_type = total_by_type if isinstance(total_by_type, dict) else {}
            if isinstance(type, NotGiven):
                matching = total if isinstance(total, int) else None
            else:
                matching = total_by_type.get(type, 0)
            return AsyncReferencesPage(
                data=[construct_bulletin(e) for e in entries if e.get("missing") is not True],
                missing=[str(e.get("id")) for e in entries if e.get("missing") is True],
                total=total if isinstance(total, int) else None,
                total_by_type=total_by_type,
                offset=offset,
                limit=limit,
                entries=len(entries),
                matching=matching,
                fetch=_fetch,
            )

        return await self._request(_REFERENCES_SPEC, cast=_build, body=params, timeout=timeout)

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
