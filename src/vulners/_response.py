"""A lean typed response wrapper for ``with_raw_response`` / streaming access.

:class:`APIResponse` exposes the transport-level facts of a call (status,
headers, raw bytes) alongside a lazy :meth:`parse` that yields the typed model.
This is the first version: the body is already buffered, so ``iter_bytes`` /
``iter_lines`` walk that buffer. Truly lazy over-the-wire streaming lands with
the archive/streaming work package.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any, Generic, TypeVar

import orjson

if TYPE_CHECKING:
    import httpx

T = TypeVar("T")


class APIResponse(Generic[T]):
    """Transport facts of a response plus a lazy parse to the typed value."""

    def __init__(
        self,
        response: httpx.Response,
        content: bytes,
        parsed: Any,
        parser: Callable[[Any], T] | None = None,
    ) -> None:
        self._response = response
        self._content = content
        self._parsed = parsed
        self._parser = parser

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def headers(self) -> httpx.Headers:
        return self._response.headers

    @property
    def http_request(self) -> httpx.Request:
        return self._response.request

    @property
    def url(self) -> httpx.URL:
        return self._response.url

    @property
    def content(self) -> bytes:
        return self._content

    @property
    def text(self) -> str:
        return self._content.decode(self._response.encoding or "utf-8", errors="replace")

    def json(self) -> Any:
        return orjson.loads(self._content) if self._content else None

    def parse(self) -> T:
        """Return the typed value (applies the resource's caster, if any)."""
        if self._parser is not None:
            return self._parser(self._parsed)
        return self._parsed

    def iter_bytes(self, chunk_size: int = 8192) -> Iterator[bytes]:
        for start in range(0, len(self._content), chunk_size):
            yield self._content[start : start + chunk_size]

    def iter_lines(self) -> Iterator[str]:
        yield from self.text.splitlines()

    def __repr__(self) -> str:
        return f"<APIResponse [{self.status_code}]>"


__all__ = ["APIResponse"]
