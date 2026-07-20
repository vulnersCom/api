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

from collections.abc import Iterable, Iterator
from typing import Any

import orjson

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


def _parse_line(line: bytes) -> Any:
    # orjson tolerates surrounding insignificant whitespace (incl. a trailing CRLF
    # \r), so a blank/whitespace-only line is the only case to skip — no per-line
    # copy via strip() on the hottest bulk-streaming path.
    if not line or line.isspace():
        return _EMPTY
    return orjson.loads(line)


# Sentinel for a blank NDJSON line (skipped), distinct from a real ``None`` record.
_EMPTY = object()


def _emit_lines(lines: Iterable[bytes]) -> Iterator[Any]:
    """Parse each raw NDJSON line, skipping blanks — the shared decoder emit step."""
    for line in lines:
        record = _parse_line(line)
        if record is not _EMPTY:
            yield record


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
        yield from _emit_lines(self._lines.push(chunk))

    def feed(self, chunk: bytes) -> Iterator[Any]:
        yield from self._emit(chunk)

    def flush(self) -> Iterator[Any]:
        yield from _emit_lines(self._lines.flush())


class GzipNdjsonDecoder:
    """Decodes NDJSON from a gzip stream (multi-member aware), chunk by chunk."""

    def __init__(self, cap: int | None = None) -> None:
        self._d = _new_gzip_decompressor()
        self._lines = _LineBuffer()
        self._cap = cap
        self._out = 0
        # Bound each inflate step to _CHUNK output when a cap is set, so a
        # decompression bomb aborts within one slice; 0 == unbounded otherwise.
        self._max_out = _CHUNK if cap is not None else 0

    def _emit(self, data: bytes) -> Iterator[Any]:
        if not data:
            return
        self._out += len(data)
        if self._cap is not None and self._out > self._cap:
            raise _cap_exceeded()
        yield from _emit_lines(self._lines.push(data))

    def feed(self, chunk: bytes) -> Iterator[Any]:
        # Inflate `chunk`, carrying a finished member's trailing bytes into a fresh
        # decompressor so a multi-member gzip stream is decoded in full (not
        # truncated at the first member). Bounded per step when a cap is set, so a
        # decompression bomb aborts before a whole slice is materialized.
        data = chunk
        while data:
            yield from self._emit(self._d.decompress(data, self._max_out))
            if self._d.eof:
                rest = self._d.unused_data
                if rest[:2] != _GZIP_MAGIC:
                    return  # trailing padding after the final member; ignore
                self._d = _new_gzip_decompressor()
                data = rest
            else:
                data = self._d.unconsumed_tail
                if not data:
                    return

    def flush(self) -> Iterator[Any]:
        yield from self._emit(self._d.flush())
        yield from _emit_lines(self._lines.flush())


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
    except ImportError as exc:  # pragma: no cover - stream-unzip is a core dependency
        raise RuntimeError(
            "multi-member zip archive support requires the 'stream-unzip' package, "
            "which is a core dependency of vulners; reinstall vulners to restore it."
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
            yield from _emit_lines(lines.push(chunk))
        yield from _emit_lines(lines.flush())


__all__ = [
    # Media-type taxonomy and the ISA-L gzip shim are the single source of truth,
    # imported by _base_client so the buffered and streamed archive paths agree.
    "_GZIP_MEDIA",
    "_ZIP_MEDIA",
    "GzipNdjsonDecoder",
    "PlainNdjsonDecoder",
    "_igzip",
    "is_zip_media",
    "iter_zip_ndjson",
    "make_ndjson_decoder",
]
