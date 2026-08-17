"""Async ``archive`` resource (unasyncd source for the sync ``archive`` resource).

Bulk collection / distributive / getsploit downloads. These endpoints return
whole compressed archives; the ``fetch_*``/``get_*`` methods match the v3
behaviour of buffering and decoding the whole body, while :meth:`aiter_collection`
streams the elements of the (gzip/zip-compressed) JSON array lazily. Large
collections can be gigabytes, so they use the archive timeout profile.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx

from ... import _download
from ..._base_client import RequestSpec, _json_loads_lenient
from ..._types import NotGiven, not_given
from . import _base

# The buffered fetch/get specs below are marked ``idempotent=False`` on purpose.
# A buffered fetch reads the whole body inside the retry loop (``_send``), so a
# mid-download ``ReadError``/``ReadTimeout`` on the storage leg would otherwise be
# retried by re-issuing the ORIGINAL request — which re-runs the vulners.com
# archive-open (the billable step) and charges a second time. ``idempotent=False``
# makes ``_retryable_exc`` refuse to retry a post-dispatch read/timeout error while
# still retrying pre-dispatch connect failures (never billed) and 408/429
# (rejected before processing). This mirrors the streaming path, whose retry loop
# (``_open_stream``) structurally covers only the pre-first-byte phase. The
# streaming (``_STREAM_*``) and cheap state (``_*_STATE``) specs keep the GET
# default: they either never re-issue after the first byte or do not bill.
_FETCH_COLLECTION = RequestSpec(
    "GET",
    "/api/v4/archive/collection",
    body_mode="query",
    response_mode="bytes",
    timeout_profile="archive",
    idempotent=False,
)
_STREAM_COLLECTION = RequestSpec(
    "GET",
    "/api/v4/archive/collection",
    body_mode="query",
    response_mode="stream",
    timeout_profile="archive",
)
_STREAM_COLLECTION_UPDATE = RequestSpec(
    "GET",
    "/api/v4/archive/collection-update",
    body_mode="query",
    response_mode="stream",
    timeout_profile="archive",
)
_FETCH_COLLECTION_UPDATE = RequestSpec(
    "GET",
    "/api/v4/archive/collection-update",
    body_mode="query",
    response_mode="bytes",
    timeout_profile="archive",
    idempotent=False,
)
_COLLECTION_STATE = RequestSpec(
    "GET", "/api/v4/archive/collection-state", body_mode="query", unwrap=("result",)
)
_FETCH_FAMILY = RequestSpec(
    "GET",
    "/api/v4/archive/family",
    body_mode="query",
    response_mode="bytes",
    timeout_profile="archive",
    idempotent=False,
)
_STREAM_FAMILY = RequestSpec(
    "GET",
    "/api/v4/archive/family",
    body_mode="query",
    response_mode="stream",
    timeout_profile="archive",
)
_FETCH_FAMILY_UPDATE = RequestSpec(
    "GET",
    "/api/v4/archive/family-update",
    body_mode="query",
    response_mode="bytes",
    timeout_profile="archive",
    idempotent=False,
)
_STREAM_FAMILY_UPDATE = RequestSpec(
    "GET",
    "/api/v4/archive/family-update",
    body_mode="query",
    response_mode="stream",
    timeout_profile="archive",
)
_FAMILY_STATE = RequestSpec(
    "GET", "/api/v4/archive/family-state", body_mode="query", unwrap=("result",)
)
_GET_COLLECTION = RequestSpec(
    "GET",
    "/api/v3/archive/collection/",
    body_mode="query",
    response_mode="bytes",
    timeout_profile="archive",
    idempotent=False,
)
_GET_DISTRIBUTIVE = RequestSpec(
    "GET",
    "/api/v3/archive/distributive/",
    body_mode="query",
    response_mode="bytes",
    timeout_profile="archive",
    idempotent=False,
)
_GETSPLOIT = RequestSpec(
    "GET",
    "/api/v3/archive/getsploit/",
    body_mode="query",
    response_mode="bytes",
    timeout_profile="archive",
    idempotent=False,
)
# Used only to resolve the storage redirect for the parallel/streaming download
# (response_mode is irrelevant there — the download bypasses the buffered loop).
_STREAM_GETSPLOIT = RequestSpec(
    "GET",
    "/api/v3/archive/getsploit/",
    body_mode="query",
    response_mode="stream",
    timeout_profile="archive",
)


def _decode_archive(value: Any) -> Any:
    """Return the archive payload parsed as JSON when possible, else raw bytes.

    The body arrives gzip/zip-compressed and is decoded to bytes by the core, then
    parsed as JSON (a collection is a single JSON array; the lenient decoder
    accepts the NaN/Infinity/big-int edges CVE data can carry). Non-JSON / binary
    bodies pass through as bytes; use :meth:`aiter_collection` for lazy,
    per-element streaming of large collections.
    """
    if isinstance(value, (bytes, bytearray)):
        try:
            return _json_loads_lenient(value)
        except ValueError:
            return bytes(value)
    return value


def _distributive(value: Any) -> list[Any]:
    # The endpoint returns application/zip whose single member is a bare JSON list
    # of {"_source": ...} objects; the core decodes the zip to those member bytes.
    if isinstance(value, (bytes, bytearray)):
        try:
            value = _json_loads_lenient(value)
        except ValueError:
            return []
    if not isinstance(value, list):
        return []
    return [item["_source"] for item in value if isinstance(item, dict) and "_source" in item]


class AsyncArchive(_base.AsyncBaseResource):
    """Download bulk archives of the Vulners database."""

    async def fetch_collection(
        self,
        type: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Download an entire collection archive by ``type`` (e.g. ``"cve"``).

        Buffers and decodes the whole archive in memory. For large collections
        prefer :meth:`aiter_collection` (lazy, per-element) or
        :meth:`download_collection` (parallel, straight to disk).

        Args:
            type: The collection type to download (e.g. ``"cve"``).

        Returns:
            The decoded collection — parsed JSON (typically a list of records)
            when the body decodes, otherwise the raw archive bytes.
        """
        return await self._request(
            _FETCH_COLLECTION, cast=_decode_archive, body={"type": type}, timeout=timeout
        )

    async def aiter_collection(
        self,
        type: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream a collection archive element by element (a JSON array).

        Unlike :meth:`fetch_collection` (which buffers and decodes the whole
        archive), this follows the archive redirect to storage, decompresses the
        body as a stream and yields each array element lazily, so a multi-gigabyte
        collection never has to be held in memory. Records delivered as raw
        Elasticsearch hits are normalized to their ``"_source"`` document.

        Args:
            type: The collection type to stream (e.g. ``"cve"``).

        Yields:
            Each collection element as a ``dict``.
        """
        async for record in self._client.stream_records(
            _STREAM_COLLECTION, params={"type": type}, timeout=timeout
        ):
            yield record

    async def download_collection(
        self,
        collection: str,
        path: str | os.PathLike[str],
        *,
        update_from: datetime | None = None,
        connections: int = 8,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> int:
        """Download a collection archive to ``path``, in parallel; return bytes written.

        The endpoint redirects to storage that supports HTTP range requests, so the
        raw (still-compressed) archive is pulled over ``connections`` concurrent
        connections and written straight to disk — saturating the link in constant
        memory — with an automatic fallback to a single stream when the storage does
        not offer ranges. Nothing is decompressed, so a multi-gigabyte collection
        downloads without ever being held in memory. Pass ``update_from`` to fetch
        only the entries changed after that moment (the collection-update endpoint).
        The write is atomic: an interrupted download never clobbers an existing file.

        Args:
            collection: The collection type to download (e.g. ``"cve"``).
            path: Destination file path; an existing file is overwritten atomically.
            update_from: When given, download the collection update since this
                moment instead of the full archive.
            connections: Number of parallel range connections (default 8). The
                SDK-owned client runs them over HTTP/1.1 so each opens a real socket
                and saturates the link; with your own ``http_client`` pass
                ``http2=False`` for the same throughput.

        Returns:
            The number of bytes written to ``path``.
        """
        if connections < 1:
            raise ValueError("connections must be >= 1")
        spec = _STREAM_COLLECTION
        params: dict[str, Any] = {"type": collection}
        if update_from is not None:
            spec = _STREAM_COLLECTION_UPDATE
            params["after"] = update_from.isoformat()
        return await _download.parallel_download_async(
            self._client,
            spec,
            os.fspath(path),
            params=params,
            connections=connections,
            timeout=timeout,
        )

    async def fetch_collection_update(
        self,
        type: str,
        after: datetime,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Download only the collection entries changed after ``after``.

        The incremental counterpart of :meth:`fetch_collection`, buffered and
        decoded in memory. Use :meth:`collection_state` to obtain the cursor to
        resume from.

        Args:
            type: The collection type to download (e.g. ``"cve"``).
            after: Only entries changed after this moment are included.

        Returns:
            The decoded update — parsed JSON (typically a list of records) when
            the body decodes, otherwise the raw archive bytes.
        """
        body = {"type": type, "after": after.isoformat()}
        return await self._request(
            _FETCH_COLLECTION_UPDATE, cast=_decode_archive, body=body, timeout=timeout
        )

    async def collection_state(
        self,
        type: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Read the sync cursor and counters for a collection.

        Returns:
            A dict with ``cursor`` (feed it back as ``after`` to the
            collection-update download), ``upload_time``, ``write_time`` and
            ``total_docs``.
        """
        return await self._request(_COLLECTION_STATE, body={"type": type}, timeout=timeout)

    async def family(
        self,
        name: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Download an entire collection-family archive by ``name``.

        Same shape as :meth:`fetch_collection`, keyed by a family name (e.g.
        ``"exploit"``, ``"unix"``, ``"software"``) instead of a single
        collection type. Buffered and decoded in memory; for large families
        prefer :meth:`iter_family` (lazy, per-element).

        Args:
            name: The collection family to download (e.g. ``"exploit"``).

        Returns:
            The decoded family archive — parsed JSON (typically a list of
            records) when the body decodes, otherwise the raw archive bytes.
        """
        return await self._request(
            _FETCH_FAMILY, cast=_decode_archive, body={"name": name}, timeout=timeout
        )

    async def family_update(
        self,
        name: str,
        after: datetime,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Download only the family entries changed after ``after`` (max 25h ago).

        The incremental counterpart of :meth:`family`. Use :meth:`family_state`
        to obtain the cursor to resume from.

        Args:
            name: The collection family to download (e.g. ``"exploit"``).
            after: Only entries changed after this moment are included; must be
                at most 25 hours ago.

        Returns:
            The decoded update — parsed JSON (typically a list of records) when
            the body decodes, otherwise the raw archive bytes.
        """
        body = {"name": name, "after": after.isoformat()}
        return await self._request(
            _FETCH_FAMILY_UPDATE, cast=_decode_archive, body=body, timeout=timeout
        )

    async def family_state(
        self,
        name: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Read the sync cursor and counters for a collection family.

        Returns:
            A dict with ``cursor`` (feed it back as ``after`` to
            :meth:`family_update`), ``upload_time``, ``write_time`` and
            ``total_docs``.
        """
        return await self._request(_FAMILY_STATE, body={"name": name}, timeout=timeout)

    # Deliberately not ``aiter``-prefixed: the method name is shared with the
    # generated sync mirror, where it is a plain generator.
    async def iter_family(
        self,
        name: str,
        *,
        update_from: datetime | None = None,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream a family archive element by element, like :meth:`aiter_collection`.

        Follows the archive redirect to storage, decompresses the body as a
        stream and yields each element lazily, so a multi-gigabyte family
        archive never has to be held in memory.

        Args:
            name: The collection family to stream (e.g. ``"exploit"``).
            update_from: When given, stream only the entries changed after this
                moment (at most 25 hours ago) instead of the whole family.

        Yields:
            Each family element as a ``dict``.
        """
        spec = _STREAM_FAMILY
        params: dict[str, Any] = {"name": name}
        if update_from is not None:
            spec = _STREAM_FAMILY_UPDATE
            params["after"] = update_from.isoformat()
        async for record in self._client.stream_records(spec, params=params, timeout=timeout):
            yield record

    async def get_collection(
        self,
        type: str,
        *,
        datefrom: str = "1976-01-01",
        dateto: str = "2199-01-01",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Download a collection over a date range (legacy v3 endpoint).

        Buffered and decoded in memory. Prefer the v4 :meth:`fetch_collection` /
        :meth:`download_collection` where available.

        Args:
            type: The collection type to download (e.g. ``"cve"``).
            datefrom: Start date (``YYYY-MM-DD``) of the range.
            dateto: End date (``YYYY-MM-DD``) of the range.

        Returns:
            The decoded collection — parsed JSON (typically a list of records)
            when the body decodes, otherwise the raw archive bytes.
        """
        body = {"type": type, "datefrom": datefrom, "dateto": dateto}
        return await self._request(
            _GET_COLLECTION, cast=_decode_archive, body=body, timeout=timeout
        )

    async def get_distributive(
        self,
        os: str,
        version: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> list[Any]:
        """Download the vulnerability distributive for an OS/version (legacy v3).

        Args:
            os: The operating system identifier (e.g. ``"debian"``, ``"centos"``).
            version: The OS version (e.g. ``"11"``).

        Returns:
            A list of the distributive's vulnerability documents (each the
            ``"_source"`` of a record).
        """
        body = {"os": os, "version": version}
        return await self._request(
            _GET_DISTRIBUTIVE, cast=_distributive, body=body, timeout=timeout
        )

    async def getsploit(
        self,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> bytes:
        """Download the raw getsploit exploit database archive (legacy v3).

        Buffers the whole archive in memory; for the full database prefer
        :meth:`download_getsploit`, which streams it to disk in parallel.

        Returns:
            The raw archive bytes (a single-member zip whose member is the
            getsploit SQLite database).
        """
        return await self._request(_GETSPLOIT, timeout=timeout)

    async def download_getsploit(
        self,
        path: str | os.PathLike[str],
        *,
        connections: int = 8,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> int:
        """Stream the getsploit database archive to ``path``, in parallel; return bytes written.

        The endpoint redirects to storage that supports HTTP range requests, so the
        archive is pulled over ``connections`` concurrent connections and written
        straight to disk — saturating the link and using constant memory — instead
        of buffering the whole database in RAM like :meth:`getsploit`. Prefer this
        for the full database; use :meth:`getsploit` only for the raw bytes in memory.
        The write is atomic (an interrupted download never clobbers an existing file),
        and the tool falls back to a single stream if the storage does not offer ranges.

        The written file is the raw archive (a single-member zip whose member is the
        getsploit SQLite database); unzip it to obtain ``getsploit.db``.

        Legacy v3 endpoint; there is no v4 equivalent and the server may retire it
        during the 4.x lifetime.

        Args:
            path: Destination file path; an existing file is overwritten atomically.
            connections: Number of parallel range connections (default 8). The
                SDK-owned client runs them over HTTP/1.1 so each opens a real socket
                and saturates the link; with your own ``http_client`` pass
                ``http2=False`` for the same throughput.

        Returns:
            The number of bytes written to ``path``.
        """
        if connections < 1:
            raise ValueError("connections must be >= 1")
        return await _download.parallel_download_async(
            self._client,
            _STREAM_GETSPLOIT,
            os.fspath(path),
            connections=connections,
            timeout=timeout,
        )


__all__ = ["AsyncArchive"]
