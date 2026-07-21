"""Async I/O client (unasyncd source for the sync :class:`SyncAPIClient`).

The sans-IO :class:`~vulners._base_client.BaseClient` holds every pure helper;
this module adds the small amount of real I/O — rate-limit pacing, the send,
capped reads, the retry loop and streaming — as :class:`AsyncAPIClient`. The sync
mirror ``_transport_client_sync.py`` (:class:`SyncAPIClient`) is generated from
this file by ``unasyncd``, so the security-relevant retry/backoff/pacing logic
stays identical across the two transports by construction. Edit this file only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from typing import Any

import httpx
from typing_extensions import Self

from ._base_client import BaseClient, RequestSpec, _mount_guard
from ._config import ClientConfig
from ._exceptions import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    ErrorInfo,
)
from ._logging import logger
from ._ratelimit_async import AsyncRateLimitBucket
from ._response import APIResponse, AsyncStreamedAPIResponse
from ._retry import _retry_timeout, _should_retry
from ._streaming import (
    is_zip_media,
    iter_zip_json_array,
    make_array_decoder,
    normalize_archive_record,
)
from ._transport import AsyncVulnersTransport
from ._types import NotGiven, Omit, not_given

# Error bodies on a streaming response are read with a small fixed cap: an error
# message never needs the multi-gigabyte archive budget, so this bounds a giant
# error body from a broken/hostile endpoint (max_response_bytes, when smaller, wins).
_ERROR_BODY_CAP = 64 * 1024


class AsyncAPIClient(BaseClient):
    """Asynchronous request loop over an ``httpx.AsyncClient``."""

    def __init__(
        self,
        config: ClientConfig,
        http_client: httpx.AsyncClient | None = None,
        buckets: dict[str, AsyncRateLimitBucket] | None = None,
    ) -> None:
        super().__init__(config)
        # Account-scoped pacing buckets. A clone (with_options) passes the parent's
        # dict so client-side rate-limit pacing is shared, not reset per variant.
        self._buckets: dict[str, AsyncRateLimitBucket] = {} if buckets is None else buckets
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
            # Wrap the caller's transport(s) so the cross-origin X-Api-Key strip,
            # set-cookie drop and SSRF redirect guard run on a BYO client too.
            _mount_guard(http_client, AsyncVulnersTransport, config.base_url)
        else:
            # h2 is a core dependency, so http2=True always works; no guard needed.
            # proxy/verify/trust_env ride on the inner transport: httpx ignores
            # client-level verify once an explicit transport is passed, and a
            # client-level proxy would mount an unguarded transport over ours.
            transport = AsyncVulnersTransport(
                httpx.AsyncHTTPTransport(
                    # retries=0: the SDK request loop is the single retry owner
                    # (idempotency rules, Retry-After, exponential backoff, on_error
                    # hooks). Letting the transport also retry the connect phase
                    # would multiply attempts (up to connect_retries x max_retries).
                    retries=0,
                    http2=config.http2,
                    proxy=config.proxy,
                    verify=config.verify,
                    trust_env=config.trust_env,
                ),
                origin=config.base_url,
            )
            self._client = httpx.AsyncClient(
                base_url=config.base_url,
                transport=transport,
                timeout=config.timeout,
                limits=config.limits,
                follow_redirects=config.follow_redirects,
                trust_env=config.trust_env,
                event_hooks={
                    "request": list(config.before_request),
                    "response": list(config.after_response),
                },
            )
            self._owns_client = True

    def _bucket_for(self, key: str) -> AsyncRateLimitBucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets.setdefault(key, AsyncRateLimitBucket())
        return bucket

    async def _send(
        self, spec: RequestSpec, request: httpx.Request
    ) -> tuple[httpx.Response, bytes]:
        if self._config.max_response_bytes is None:
            response = await self._client.send(request)
            return response, response.content
        response = await self._client.send(request, stream=True)
        try:
            self._reject_declared_length(
                response.headers.get("content-length"), response.status_code
            )
            buf = bytearray()
            async for chunk in response.aiter_bytes():
                buf += chunk
                self._guard_cap(len(buf), response.status_code)
        finally:
            await response.aclose()
        return response, bytes(buf)

    async def _emit_error(self, error: Exception) -> None:
        # on_error hooks observe the final failure of the request loop (after
        # retries are exhausted); an exception raised by a hook propagates to
        # the caller in place of the original error.
        for hook in self._config.on_error:
            await hook(error)

    async def _send_with_retries(
        self, spec: RequestSpec, request: httpx.Request, retries: int
    ) -> tuple[httpx.Response, bytes, Any]:
        bucket = self._bucket_for(self._ratelimit_key(spec))
        attempt = 0
        while True:
            await bucket.consume(self._config.max_rate_limit_wait)
            try:
                response, content = await self._send(spec, request)
            except httpx.TimeoutException as exc:
                error: APIConnectionError = APITimeoutError(f"Request timed out: {exc}")
                if attempt < retries and self._retryable_exc(exc, spec):
                    attempt += 1
                    await self._sleep(_retry_timeout(attempt))
                    continue
                await self._emit_error(error)
                raise error from exc
            except httpx.TransportError as exc:
                error = APIConnectionError(f"Connection error: {exc}")
                if attempt < retries and self._retryable_exc(exc, spec):
                    attempt += 1
                    await self._sleep(_retry_timeout(attempt))
                    continue
                await self._emit_error(error)
                raise error from exc
            self._update_bucket_from_headers(bucket, response)
            try:
                parsed = self._process_response(spec, response, content)
            except APIStatusError as err:
                info = ErrorInfo(status_code=err.status_code, error_code=err.error_code)
                if attempt < retries and _should_retry(
                    info, response.headers, idempotent=self._idempotent(spec)
                ):
                    attempt += 1
                    logger.debug(
                        "retrying %s %s after status %s", spec.method, spec.path, err.status_code
                    )
                    await self._sleep(_retry_timeout(attempt, response.headers))
                    continue
                await self._emit_error(err)
                raise
            return response, content, parsed

    async def request(
        self,
        spec: RequestSpec,
        *,
        cast: Callable[[Any], Any] | None = None,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        files: Any = None,
        headers: Mapping[str, str | Omit] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
        max_retries: int | None = None,
    ) -> Any:
        retries = self._config.max_retries if max_retries is None else max_retries
        request = self._build_request(
            spec, params=params, body=body, files=files, headers=headers, timeout=timeout
        )
        _, _, parsed = await self._send_with_retries(spec, request, retries)
        return cast(parsed) if cast is not None else parsed

    async def request_with_response(
        self,
        spec: RequestSpec,
        *,
        cast: Callable[[Any], Any] | None = None,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        files: Any = None,
        headers: Mapping[str, str | Omit] | None = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
        max_retries: int | None = None,
    ) -> APIResponse[Any]:
        retries = self._config.max_retries if max_retries is None else max_retries
        request = self._build_request(
            spec, params=params, body=body, files=files, headers=headers, timeout=timeout
        )
        response, content, parsed = await self._send_with_retries(spec, request, retries)
        return APIResponse(response, content, parsed, cast)

    async def _read_error_capped(self, response: httpx.Response) -> bytes:
        # Bound an error body to a small fixed size (or max_response_bytes when
        # smaller): an error message never needs the archive budget, and this stops
        # a broken/hostile endpoint from streaming a giant error body into memory
        # on the streaming error path (where a plain aread() would be unbounded).
        cap = self._config.max_response_bytes
        limit = _ERROR_BODY_CAP if cap is None else min(cap, _ERROR_BODY_CAP)
        buf = bytearray()
        async for chunk in response.aiter_bytes():
            buf += chunk
            if len(buf) >= limit:
                break
        return bytes(buf[:limit])

    async def _open_stream(self, spec: RequestSpec, request: httpx.Request) -> httpx.Response:
        """Open a streaming response through the retry loop, returning live headers.

        Retries the *opening* phase — connect/timeout errors and a retryable error
        status received before any record is yielded — so a stream gets the same
        resilience and error normalization (typed errors, on_error) as a buffered
        request. Once the caller consumes records there is no retry (that would
        duplicate rows), so only this pre-first-byte phase is covered here.
        """
        bucket = self._bucket_for(self._ratelimit_key(spec))
        retries = self._config.max_retries
        attempt = 0
        while True:
            await bucket.consume(self._config.max_rate_limit_wait)
            try:
                response = await self._client.send(request, stream=True)
            except httpx.TimeoutException as exc:
                error: APIConnectionError = APITimeoutError(f"Request timed out: {exc}")
                if attempt < retries and self._retryable_exc(exc, spec):
                    attempt += 1
                    await self._sleep(_retry_timeout(attempt))
                    continue
                await self._emit_error(error)
                raise error from exc
            except httpx.TransportError as exc:
                error = APIConnectionError(f"Connection error: {exc}")
                if attempt < retries and self._retryable_exc(exc, spec):
                    attempt += 1
                    await self._sleep(_retry_timeout(attempt))
                    continue
                await self._emit_error(error)
                raise error from exc
            self._update_bucket_from_headers(bucket, response)
            if response.status_code < 400:
                return response
            # Error status before any record: bounded read, retry if retryable.
            content = await self._read_error_capped(response)
            info = ErrorInfo(status_code=response.status_code, error_code=None)
            await response.aclose()
            if attempt < retries and _should_retry(
                info, response.headers, idempotent=self._idempotent(spec)
            ):
                attempt += 1
                await self._sleep(_retry_timeout(attempt, response.headers))
                continue
            try:
                self._raise_stream_error(response, content)
            except APIStatusError as err:
                await self._emit_error(err)
                raise

    async def stream_records(
        self,
        spec: RequestSpec,
        *,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> AsyncIterator[Any]:
        """Lazily yield the elements of a streamed bulk-archive JSON array."""
        request = self._build_request(spec, params=params, body=body, timeout=timeout)
        response = await self._open_stream(spec, request)
        try:
            media = self._media_type(response)
            cap = self._config.max_response_bytes
            if is_zip_media(media):
                # simplification: the ZIP path buffers the whole (compressed) body
                # before stream-unzip walks it — stream-unzip is a sync pull-based
                # generator with no async driver. The real Vulners v4 archive is
                # single-member gzip, fully streamed in the else branch; ZIP is the
                # v3/defensive path. Bounded by max_response_bytes when set.
                buf = bytearray()
                async for chunk in response.aiter_bytes():
                    buf += chunk
                    if cap is not None:
                        self._guard_cap(len(buf), response.status_code)
                for record in iter_zip_json_array(bytes(buf), cap):
                    yield normalize_archive_record(record)
            else:
                # The decoder inflates and parses the JSON array lazily and
                # enforces the cap on the decompressed byte count.
                decoder = make_array_decoder(media, cap)
                async for chunk in response.aiter_bytes():
                    for record in decoder.feed(chunk):
                        yield normalize_archive_record(record)
                # feed() drains each chunk fully (ijson emits every element at its
                # closing brace), so flush() is a no-op for the array decoders; the
                # call is the decoder-protocol contract, kept for a buffering decoder.
                for record in decoder.flush():  # pragma: no cover
                    yield normalize_archive_record(record)
        finally:
            await response.aclose()

    def stream_response(
        self,
        spec: RequestSpec,
        *,
        cast: Callable[[Any], Any] | None = None,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        files: Any = None,
        timeout: float | httpx.Timeout | None | NotGiven = not_given,
    ) -> AsyncStreamContext:
        """A context manager yielding a live :class:`AsyncStreamedAPIResponse`."""
        request = self._build_request(
            spec, params=params, body=body, files=files, timeout=timeout
        )
        return AsyncStreamContext(self, spec, request, cast)

    @staticmethod
    async def _sleep(seconds: float) -> None:
        import asyncio

        await asyncio.sleep(seconds)

    async def get(self, path: str, *, params: Mapping[str, Any] | None = None, **kw: Any) -> Any:
        return await self.request(
            RequestSpec("GET", path, body_mode="query"), params=params, **kw
        )

    async def post(self, path: str, *, body: Any = None, **kw: Any) -> Any:
        return await self.request(RequestSpec("POST", path, body_mode="json"), body=body, **kw)

    async def put(self, path: str, *, body: Any = None, **kw: Any) -> Any:
        return await self.request(RequestSpec("PUT", path, body_mode="json"), body=body, **kw)

    async def delete(
        self, path: str, *, params: Mapping[str, Any] | None = None, **kw: Any
    ) -> Any:
        return await self.request(
            RequestSpec("DELETE", path, body_mode="query"), params=params, **kw
        )

    # -- lifecycle ---------------------------------------------------------

    @property
    def is_closed(self) -> bool:
        return self._client.is_closed

    async def aclose(self) -> None:
        if self._owns_client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


class AsyncStreamContext:
    """Async context manager that opens a stream and yields a live response."""

    def __init__(
        self,
        client: AsyncAPIClient,
        spec: RequestSpec,
        request: httpx.Request,
        cast: Callable[[Any], Any] | None,
    ) -> None:
        self._client = client
        self._spec = spec
        self._request = request
        self._cast = cast
        self._response: httpx.Response | None = None

    async def __aenter__(self) -> AsyncStreamedAPIResponse[Any]:
        client = self._client
        # Route the open through the retry loop (connect/timeout/retryable-status),
        # with bounded error reads — same resilience as a buffered request.
        response = await client._open_stream(self._spec, self._request)
        self._response = response
        return AsyncStreamedAPIResponse(response, client._stream_parser(self._spec, self._cast))

    async def __aexit__(self, *exc: object) -> None:
        if self._response is not None:
            await self._response.aclose()


__all__ = ["AsyncAPIClient", "AsyncStreamContext"]
