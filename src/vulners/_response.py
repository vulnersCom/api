"""Typed response wrappers for ``with_raw_response`` / ``with_streaming_response``.

* :class:`APIResponse` — a *buffered* view: the body is already read, so it
  exposes status/headers/content plus a lazy :meth:`parse` to the typed value.
  Backs ``resource.with_raw_response.method(...)``.
* :class:`StreamedAPIResponse` / :class:`AsyncStreamedAPIResponse` — a *live*
  view over an un-read response, exposing ``iter_bytes`` / ``iter_lines`` /
  ``iter_text`` (async: ``aiter_*``) that walk the body straight off the wire,
  plus ``parse`` (reads the body, then runs the normal decode pipeline). These
  are handed out from a context manager (see ``client.stream_response``) so the
  connection is always released on exit. Backs
  ``resource.with_streaming_response.method(...)``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator
from typing import TYPE_CHECKING, Any, Generic, TypeVar

import orjson

if TYPE_CHECKING:
    import httpx

T = TypeVar("T")

# Runs a read body back through the client's decode pipeline (unwrap + cast).
ParseFn = Callable[["httpx.Response", bytes], Any]


class _BaseResponse:
    """Shared read-only passthrough of the underlying ``httpx.Response`` facts."""

    _response: httpx.Response

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


class APIResponse(_BaseResponse, Generic[T]):
    """Transport facts of a buffered response plus a lazy parse to the value."""

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


class StreamedAPIResponse(_BaseResponse, Generic[T]):
    """A live, un-buffered view over a streaming response (sync)."""

    def __init__(self, response: httpx.Response, parse: ParseFn) -> None:
        self._response = response
        self._parse = parse
        self._content: bytes | None = None

    def iter_bytes(self, chunk_size: int | None = None) -> Iterator[bytes]:
        yield from self._response.iter_bytes(chunk_size)

    def iter_text(self, chunk_size: int | None = None) -> Iterator[str]:
        yield from self._response.iter_text(chunk_size)

    def iter_lines(self) -> Iterator[str]:
        yield from self._response.iter_lines()

    def read(self) -> bytes:
        if self._content is None:
            self._content = self._response.read()
        return self._content

    def parse(self) -> T:
        return self._parse(self._response, self.read())

    def close(self) -> None:
        self._response.close()

    def __repr__(self) -> str:
        return f"<StreamedAPIResponse [{self.status_code}]>"


class AsyncStreamedAPIResponse(_BaseResponse, Generic[T]):
    """A live, un-buffered view over a streaming response (async)."""

    def __init__(self, response: httpx.Response, parse: ParseFn) -> None:
        self._response = response
        self._parse = parse
        self._content: bytes | None = None

    async def iter_bytes(self, chunk_size: int | None = None) -> AsyncIterator[bytes]:
        async for chunk in self._response.aiter_bytes(chunk_size):
            yield chunk

    async def iter_text(self, chunk_size: int | None = None) -> AsyncIterator[str]:
        async for chunk in self._response.aiter_text(chunk_size):
            yield chunk

    async def iter_lines(self) -> AsyncIterator[str]:
        async for line in self._response.aiter_lines():
            yield line

    async def read(self) -> bytes:
        if self._content is None:
            self._content = await self._response.aread()
        return self._content

    async def parse(self) -> T:
        return self._parse(self._response, await self.read())

    async def close(self) -> None:
        await self._response.aclose()

    def __repr__(self) -> str:
        return f"<AsyncStreamedAPIResponse [{self.status_code}]>"


__all__ = ["APIResponse", "AsyncStreamedAPIResponse", "StreamedAPIResponse"]
