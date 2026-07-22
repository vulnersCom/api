"""Sans-IO JSON-array stream decoders shared by the sync and async request loops.

A bulk archive body is a single JSON *array* (pretty-printed, one element per
line), delivered either gzip-compressed (the Vulners v4 archive:
``application/x-gzip-compressed``) or zip-compressed (the v3 archive:
``application/x-zip-compressed``, whose single inner ``<type>.json`` member holds
the same array). The decoders here are *fed* raw byte chunks one at a time and
yield each parsed array element, so the same decoder drives
``for chunk in resp.iter_bytes()`` (sync) and ``async for chunk in
resp.aiter_bytes()`` (async) without duplicating the decode logic. Elements are
streamed with ijson's push (coroutine) parser, so a multi-gigabyte array is never
fully buffered. The opt-in ``max_response_bytes`` cap is enforced on the
decompressed byte count — the decompression-bomb guard ported from
``vulners.base``.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import ijson

from ._exceptions import APIResponseValidationError

# ISA-L accelerated gzip/zlib, a drop-in for the stdlib modules on the multi-GB
# archive inflate hot path. isal is a core dependency, so the stdlib fallback is
# defensive only (e.g. an odd platform without a wheel).
try:
    from isal import igzip as _igzip  # gzip module: whole-file, multi-member decompress
    from isal import isal_zlib as _zlib  # zlib module: incremental decompressobj
except ImportError:  # pragma: no cover - isal is a core dep; stdlib fallback
    import gzip as _igzip  # type: ignore[no-redef]
    import zlib as _zlib  # type: ignore[no-redef]

# Slice size for bounded gzip inflate, matching vulners.base._inflate_capped.
_CHUNK = 1 << 18

# gzip member magic: distinguishes a genuine concatenated next member (multi-member
# stream) from trailing padding once a member ends.
_GZIP_MAGIC = b"\x1f\x8b"

_GZIP_MEDIA = frozenset(
    {"application/gzip", "application/x-gzip", "application/x-gzip-compressed"}
)
_ZIP_MEDIA = frozenset({"application/zip", "application/x-zip-compressed"})


def _new_gzip_decompressor() -> Any:
    """A fresh single-member gzip stream decompressor (ISA-L when available)."""
    return _zlib.decompressobj(wbits=31)


def _cap_exceeded() -> APIResponseValidationError:
    return APIResponseValidationError("decompressed response exceeds max_response_bytes")


class _JsonArrayItems:
    """Streams the elements of a top-level JSON array from decompressed bytes.

    Bytes are pushed via :meth:`feed`; each element of the top-level array is
    yielded as soon as ijson has parsed it (via ijson's coroutine/push parser),
    so the whole array is never buffered. ``cap`` bounds the total decompressed
    bytes fed before the read aborts (the decompression-bomb guard).
    """

    def __init__(self, cap: int | None) -> None:
        # sendable_list is ijson's push-parser target: each parsed 'item' (a
        # top-level array element) is appended, and we drain it after each send.
        self._target = ijson.sendable_list()
        self._coro = ijson.items_coro(self._target, "item")
        self._cap = cap
        self._seen = 0

    def _drain(self) -> Iterator[Any]:
        if self._target:
            yield from self._target
            del self._target[:]

    def feed(self, data: bytes) -> Iterator[Any]:
        if not data:
            return
        self._seen += len(data)
        if self._cap is not None and self._seen > self._cap:
            raise _cap_exceeded()
        self._coro.send(data)
        yield from self._drain()

    def flush(self) -> Iterator[Any]:
        # Called exactly once at end-of-stream: finalize the push parser (which
        # completes any pending element) and drain what remains.
        self._coro.close()
        yield from self._drain()


class PlainJsonArrayDecoder:
    """Parses a JSON array from already-inflated (or uncompressed) bytes."""

    def __init__(self, cap: int | None = None) -> None:
        self._items = _JsonArrayItems(cap)

    def feed(self, chunk: bytes) -> Iterator[Any]:
        yield from self._items.feed(chunk)

    def flush(self) -> Iterator[Any]:
        yield from self._items.flush()


class GzipJsonArrayDecoder:
    """Parses a JSON array from a gzip stream (multi-member aware), chunk by chunk."""

    def __init__(self, cap: int | None = None) -> None:
        self._d = _new_gzip_decompressor()
        self._items = _JsonArrayItems(cap)
        # Bound each inflate step to _CHUNK output when a cap is set, so a
        # decompression bomb aborts within one slice; 0 == unbounded otherwise.
        self._max_out = _CHUNK if cap is not None else 0

    def feed(self, chunk: bytes) -> Iterator[Any]:
        # Inflate `chunk`, carrying a finished member's trailing bytes into a fresh
        # decompressor so a multi-member gzip stream is decoded in full (not
        # truncated at the first member). Bounded per step when a cap is set, so a
        # decompression bomb aborts before a whole slice is materialized.
        data = chunk
        while data:
            yield from self._items.feed(self._d.decompress(data, self._max_out))
            if self._d.eof:
                rest = self._d.unused_data
                if rest[:2] != _GZIP_MAGIC:
                    # After the final member, tolerate only NUL padding; any other
                    # trailing bytes mean this is not a clean archive (a corrupt or
                    # spoofed tail must not pass as a valid download).
                    if rest.strip(b"\x00"):
                        raise APIResponseValidationError(
                            "trailing garbage after the gzip archive"
                        )
                    return
                self._d = _new_gzip_decompressor()
                data = rest
            else:
                data = self._d.unconsumed_tail
                if not data:
                    return

    def flush(self) -> Iterator[Any]:
        yield from self._items.feed(self._d.flush())
        if not self._d.eof:
            # The gzip stream ended before its trailer: the JSON may parse, but the
            # CRC/length trailer was never reached, so a truncated download (dropped
            # connection, short archive) would otherwise look successful. Treat it
            # as a corrupt archive instead of silently yielding a partial dataset.
            raise APIResponseValidationError(
                "truncated gzip archive: stream ended before the gzip trailer"
            )
        yield from self._items.flush()


def make_array_decoder(
    media: str, cap: int | None
) -> PlainJsonArrayDecoder | GzipJsonArrayDecoder:
    """Pick the decoder for *media* (gzip stream vs. already-inflated JSON array)."""
    if media in _GZIP_MEDIA:
        return GzipJsonArrayDecoder(cap)
    return PlainJsonArrayDecoder(cap)


def is_zip_media(media: str) -> bool:
    return media in _ZIP_MEDIA


def normalize_archive_record(record: Any) -> Any:
    """Unwrap the Elasticsearch-hit envelope some archive records carry.

    Some archive exports stream raw ES hits — ``{"_index": ..., "_id": ...,
    "_source": {...}}``, every key underscore-prefixed with the document itself
    under ``"_source"`` — instead of bare documents. Return the inner document
    for that shape; any other record (including a document that merely contains
    a ``_source`` field among regular keys) passes through unchanged, so the
    heuristic can only unwrap, never corrupt.
    """
    if (
        isinstance(record, dict)
        and isinstance(record.get("_source"), dict)
        and all(key.startswith("_") for key in record)
    ):
        return record["_source"]
    return record


def _import_stream_unzip() -> Any:
    try:
        from stream_unzip import stream_unzip
    except ImportError as exc:  # pragma: no cover - stream-unzip is a core dependency
        raise RuntimeError(
            "zip archive support requires the 'stream-unzip' package, which is a "
            "core dependency of vulners; reinstall vulners to restore it."
        ) from exc
    return stream_unzip


def iter_zip_json_array(body: bytes, cap: int | None = None) -> Iterator[Any]:
    """Yield JSON-array elements from a (buffered) zip archive's inner member(s).

    simplification: the zip body is buffered before ``stream-unzip`` walks it,
    because ``stream-unzip`` is a sync pull-based generator with no async driver;
    the read is still bounded by ``max_response_bytes``. The real Vulners v4
    archive is single-member gzip (fully streamed above); zip is the v3/defensive
    path. Upgrade: an async-native zip decoder if a zip archive endpoint turns hot.
    """
    stream_unzip = _import_stream_unzip()
    seen = 0
    for _name, _size, chunks in stream_unzip([body]):
        # Each member is its own JSON array, so it gets a fresh push parser; the
        # cap is tracked cumulatively across members here (the real archive has a
        # single member, so this only matters for the defensive multi-member case).
        items = _JsonArrayItems(None)
        for chunk in chunks:
            seen += len(chunk)
            if cap is not None and seen > cap:
                raise _cap_exceeded()
            yield from items.feed(chunk)
        yield from items.flush()


__all__ = [
    # Media-type taxonomy and the ISA-L gzip shim are the single source of truth,
    # imported by _base_client so the buffered and streamed archive paths agree.
    "_GZIP_MEDIA",
    "_ZIP_MEDIA",
    "GzipJsonArrayDecoder",
    "PlainJsonArrayDecoder",
    "_igzip",
    "is_zip_media",
    "iter_zip_json_array",
    "make_array_decoder",
    "normalize_archive_record",
]
