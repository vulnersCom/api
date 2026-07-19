"""Sans-IO NDJSON stream decoders shared by the sync and async request loops.

Bulk archive bodies are line-delimited JSON, delivered either as a single-member
gzip stream (the Vulners archive: GCS ``application/x-gzip-compressed``), as a
multi-member zip, or already inflated by httpx (``Content-Encoding``). The
decoders here are *fed* raw byte chunks one at a time and yield parsed records,
so the same decoder drives ``for chunk in resp.iter_bytes()`` (sync) and
``async for chunk in resp.aiter_bytes()`` (async) without duplicating the decode
logic. The opt-in ``max_response_bytes`` cap is enforced on the decoded/inflated
output — the proven decompression-bomb guard ported from ``vulners.base``.
"""

from __future__ import annotations

import zlib
from collections.abc import Iterator
from typing import Any

import orjson

from ._exceptions import APIResponseValidationError

# Slice size for bounded gzip inflate, matching vulners.base._inflate_capped.
_CHUNK = 1 << 18

_GZIP_MEDIA = frozenset(
    {"application/gzip", "application/x-gzip", "application/x-gzip-compressed"}
)
_ZIP_MEDIA = frozenset({"application/zip", "application/x-zip-compressed"})


def _cap_exceeded() -> APIResponseValidationError:
    return APIResponseValidationError("decompressed response exceeds max_response_bytes")


def _parse_line(line: bytes) -> Any:
    stripped = line.strip()
    if not stripped:
        return _EMPTY
    return orjson.loads(stripped)


# Sentinel for a blank NDJSON line (skipped), distinct from a real ``None`` record.
_EMPTY = object()


class _LineBuffer:
    """Accumulates bytes and yields complete newline-delimited lines."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def push(self, data: bytes) -> list[bytes]:
        self._buf += data
        lines: list[bytes] = []
        while True:
            nl = self._buf.find(b"\n")
            if nl < 0:
                break
            lines.append(bytes(self._buf[:nl]))
            del self._buf[: nl + 1]
        return lines

    def flush(self) -> list[bytes]:
        if not self._buf:
            return []
        line = bytes(self._buf)
        self._buf = bytearray()
        return [line]


class PlainNdjsonDecoder:
    """Decodes NDJSON from already-inflated (or uncompressed) bytes."""

    def __init__(self, cap: int | None = None) -> None:
        self._lines = _LineBuffer()
        self._cap = cap
        self._seen = 0

    def _emit(self, chunk: bytes) -> Iterator[Any]:
        self._seen += len(chunk)
        if self._cap is not None and self._seen > self._cap:
            raise _cap_exceeded()
        for line in self._lines.push(chunk):
            record = _parse_line(line)
            if record is not _EMPTY:
                yield record

    def feed(self, chunk: bytes) -> Iterator[Any]:
        yield from self._emit(chunk)

    def flush(self) -> Iterator[Any]:
        for line in self._lines.flush():
            record = _parse_line(line)
            if record is not _EMPTY:
                yield record


class GzipNdjsonDecoder:
    """Decodes NDJSON from a single-member gzip stream, chunk by chunk."""

    def __init__(self, cap: int | None = None) -> None:
        self._d = zlib.decompressobj(wbits=31)
        self._lines = _LineBuffer()
        self._cap = cap
        self._out = 0

    def _emit(self, data: bytes) -> Iterator[Any]:
        if not data:
            return
        self._out += len(data)
        if self._cap is not None and self._out > self._cap:
            raise _cap_exceeded()
        for line in self._lines.push(data):
            record = _parse_line(line)
            if record is not _EMPTY:
                yield record

    def feed(self, chunk: bytes) -> Iterator[Any]:
        if self._cap is None:
            yield from self._emit(self._d.decompress(chunk))
            return
        # Bounded inflate: expand in cap-sized slices and drain the tail so a
        # decompression bomb aborts before the whole chunk is materialized.
        for i in range(0, len(chunk), _CHUNK):
            yield from self._emit(self._d.decompress(chunk[i : i + _CHUNK], _CHUNK))
            while self._d.unconsumed_tail:
                yield from self._emit(self._d.decompress(self._d.unconsumed_tail, _CHUNK))

    def flush(self) -> Iterator[Any]:
        yield from self._emit(self._d.flush())
        for line in self._lines.flush():
            record = _parse_line(line)
            if record is not _EMPTY:
                yield record


def make_ndjson_decoder(media: str, cap: int | None) -> PlainNdjsonDecoder | GzipNdjsonDecoder:
    """Pick the decoder for *media* (gzip stream vs. already-inflated NDJSON)."""
    if media in _GZIP_MEDIA:
        return GzipNdjsonDecoder(cap)
    return PlainNdjsonDecoder(cap)


def is_zip_media(media: str) -> bool:
    return media in _ZIP_MEDIA


def _import_stream_unzip() -> Any:
    try:
        from stream_unzip import stream_unzip
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise RuntimeError(
            "multi-member zip archive support requires the 'stream-unzip' package. "
            "Install it with: pip install vulners[stream-zip]"
        ) from exc
    return stream_unzip


def iter_zip_ndjson(body: bytes, cap: int | None = None) -> Iterator[Any]:
    """Yield NDJSON records from a (buffered) multi-member zip archive.

    simplification: the zip body is buffered before ``stream-unzip`` walks it,
    because ``stream-unzip`` is a sync pull-based generator with no async driver;
    the read is still bounded by ``max_response_bytes``. The real Vulners archive
    is single-member gzip (fully streamed above); zip is the defensive path.
    Upgrade: an async-native zip decoder if a zip archive endpoint turns hot.
    """
    stream_unzip = _import_stream_unzip()
    seen = 0
    for _name, _size, chunks in stream_unzip([body]):
        lines = _LineBuffer()
        for chunk in chunks:
            seen += len(chunk)
            if cap is not None and seen > cap:
                raise _cap_exceeded()
            for line in lines.push(chunk):
                record = _parse_line(line)
                if record is not _EMPTY:
                    yield record
        for line in lines.flush():
            record = _parse_line(line)
            if record is not _EMPTY:
                yield record


__all__ = [
    "GzipNdjsonDecoder",
    "PlainNdjsonDecoder",
    "is_zip_media",
    "iter_zip_ndjson",
    "make_ndjson_decoder",
]
