"""Async ``archive`` resource (unasyncd source for the sync ``archive`` resource).

Bulk collection / distributive / getsploit downloads. These endpoints return
whole compressed archives; the ``fetch_*``/``get_*`` methods match the v3
behaviour of buffering and decoding the whole body, while :meth:`aiter_collection`
streams NDJSON records lazily. Large collections can be gigabytes, so they use
the archive timeout profile.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx
import orjson

from ..._base_client import RequestSpec
from ..._types import NotGiven, not_given
from . import _base

_FETCH_COLLECTION = RequestSpec(
    "GET",
    "/api/v4/archive/collection",
    body_mode="query",
    response_mode="bytes",
    timeout_profile="archive",
)
_STREAM_COLLECTION = RequestSpec(
    "GET",
    "/api/v4/archive/collection",
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
)
_GET_COLLECTION = RequestSpec(
    "GET",
    "/api/v3/archive/collection/",
    body_mode="query",
    response_mode="bytes",
    timeout_profile="archive",
)
_GET_DISTRIBUTIVE = RequestSpec(
    "GET",
    "/api/v3/archive/distributive/",
    body_mode="query",
    response_mode="bytes",
    timeout_profile="archive",
)
_GETSPLOIT = RequestSpec(
    "GET",
    "/api/v3/archive/getsploit/",
    body_mode="query",
    response_mode="bytes",
    timeout_profile="archive",
)


def _decode_archive(value: Any) -> Any:
    """Return the archive payload parsed as JSON when possible, else raw bytes.

    The body arrives gzip/zip-compressed and is decoded to bytes by the core;
    small collections are a single JSON document, so parse them. NDJSON / binary
    bodies pass through as bytes; use :meth:`aiter_collection` for lazy per-record
    streaming of large collections.
    """
    if isinstance(value, (bytes, bytearray)):
        try:
            return orjson.loads(value)
        except orjson.JSONDecodeError:
            return bytes(value)
    return value


def _distributive(value: Any) -> list[Any]:
    # The endpoint returns application/zip whose single member is a bare JSON list
    # of {"_source": ...} objects; the core decodes the zip to those member bytes.
    if isinstance(value, (bytes, bytearray)):
        try:
            value = orjson.loads(value)
        except orjson.JSONDecodeError:
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
        """Download an entire collection archive by ``type`` (e.g. ``"cve"``)."""
        return await self._request(
            _FETCH_COLLECTION, cast=_decode_archive, body={"type": type}, timeout=timeout
        )

    async def aiter_collection(
        self,
        type: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream a collection archive as NDJSON records, one at a time.

        Unlike :meth:`fetch_collection` (which buffers and decodes the whole
        archive), this follows the archive redirect to storage and yields each
        parsed record lazily, so a multi-gigabyte collection never has to be held
        in memory. Records that are not JSON objects are yielded as-is.
        """
        async for record in self._client.stream_records(
            _STREAM_COLLECTION, params={"type": type}, timeout=timeout
        ):
            yield record

    async def fetch_collection_update(
        self,
        type: str,
        after: datetime,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Download only the collection entries changed after ``after``."""
        body = {"type": type, "after": after.isoformat()}
        return await self._request(
            _FETCH_COLLECTION_UPDATE, cast=_decode_archive, body=body, timeout=timeout
        )

    async def get_collection(
        self,
        type: str,
        *,
        datefrom: str = "1976-01-01",
        dateto: str = "2199-01-01",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Download a collection over a date range (legacy v3 endpoint)."""
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
        """Download the vulnerability distributive for an OS/version (legacy v3)."""
        body = {"os": os, "version": version}
        return await self._request(
            _GET_DISTRIBUTIVE, cast=_distributive, body=body, timeout=timeout
        )

    async def getsploit(
        self,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> bytes:
        """Download the raw getsploit exploit database archive (legacy v3)."""
        return await self._request(_GETSPLOIT, timeout=timeout)


__all__ = ["AsyncArchive"]
